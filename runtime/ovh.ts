import { createHash } from 'node:crypto';
import { z } from 'zod';
import { OvhConnectionInfo } from '../shared/ovh.js';
import type { OvhInfo } from '../shared/ovh.js';
import { fail } from '../server/errors.js';
import { publicUrl, responseJson } from '../server/transport.js';
import type { OutboundRequest, Transport } from '../server/transport.js';

export interface OvhCredentials { applicationKey: string; applicationSecret: string; consumerKey: string }

export function ovhSignature(credentials: OvhCredentials, request: OutboundRequest, timestamp: number) {
  const body = request.body === undefined ? '' : typeof request.body === 'string' ? request.body : Buffer.from(request.body).toString('utf8');
  return '$1$' + createHash('sha1').update([credentials.applicationSecret, credentials.consumerKey,
    request.method ?? 'GET', request.url, body, String(timestamp)].join('+')).digest('hex');
}

const authentication = z.object({
  account: z.string().min(1), identities: z.array(z.string()),
  user: z.string().nullable(), description: z.string().nullable(), roles: z.array(z.string()).nullable(),
});
const credential = OvhConnectionInfo.pick({ credentialId: true, rules: true, allowedIPs: true })
  .extend({ status: z.literal('validated'), expiration: z.iso.datetime().nullable() });

export class OvhApi {
  private clock = new Map<string, { difference: number; checkedAt: number }>();
  constructor(readonly transport: Transport) {}

  async send(base: string, credentials: OvhCredentials, input: OutboundRequest) {
    const root = publicUrl(base), destination = publicUrl(input.url);
    if (destination.origin !== root.origin || !destination.pathname.startsWith(root.pathname.replace(/\/$/, '') + '/'))
      fail(400, 'invalid_destination', 'Use the API endpoint selected for this OVH account.');
    const now = Date.now();
    let clock = this.clock.get(base);
    if (!clock || now - clock.checkedAt >= 60_000) {
      const response = await this.transport.send({ url: base + '/auth/time', signal: input.signal });
      if (response.status !== 200) fail(502, 'service_unavailable', 'OVHcloud could not provide its current time.');
      let time: unknown;
      try { time = JSON.parse(Buffer.from(response.body).toString('utf8')); } catch {}
      if (!Number.isSafeInteger(time) || Number(time) <= 0) fail(502, 'invalid_response', 'OVHcloud returned an invalid time.');
      clock = { difference: Number(time) - Math.floor(Date.now() / 1000), checkedAt: Date.now() };
      this.clock.set(base, clock);
    }
    const timestamp = Math.floor(Date.now() / 1000) + clock.difference;
    const request = { ...input, method: input.method ?? 'GET' };
    return this.transport.send({ ...request, headers: { ...request.headers,
      'X-Ovh-Application': credentials.applicationKey, 'X-Ovh-Consumer': credentials.consumerKey,
      'X-Ovh-Timestamp': String(timestamp), 'X-Ovh-Signature': ovhSignature(credentials, request, timestamp) } });
  }

  async inspect(base: string, credentials: OvhCredentials, signal: AbortSignal): Promise<OvhInfo> {
    const details = await this.send(base, credentials, { url: base + '/auth/details', signal });
    const current = await this.send(base, credentials, { url: base + '/auth/currentCredential', signal });
    if ([details, current].some(response => response.status === 401 || response.status === 403))
      fail(400, 'invalid_credentials', 'Check the OVHcloud keys, account region, and API permissions.');
    if (details.status !== 200 || current.status !== 200)
      fail(502, 'service_response', 'OVHcloud could not confirm this connection.');
    const identity = authentication.safeParse(responseJson(details)), access = credential.safeParse(responseJson(current));
    if (!identity.success || !access.success) fail(502, 'invalid_response', 'OVHcloud returned invalid authentication details.');
    const expiresAt = access.data.expiration === null ? null : Date.parse(access.data.expiration);
    if (expiresAt !== null && expiresAt <= Date.now()) fail(400, 'invalid_credentials', 'This OVHcloud API key has expired.');
    return OvhConnectionInfo.parse({ ...identity.data, identities: [...identity.data.identities].sort(),
      roles: identity.data.roles ? [...identity.data.roles].sort() : null,
      credentialId: access.data.credentialId, rules: [...access.data.rules].sort((a, b) =>
        (a.method + ' ' + a.path).localeCompare(b.method + ' ' + b.path)),
      allowedIPs: access.data.allowedIPs ? [...access.data.allowedIPs].sort() : null, expiresAt });
  }
}
