import { createHash } from 'node:crypto';
import { fail } from '../server/errors.js';
import { publicUrl } from '../server/transport.js';
import type { OutboundRequest, Transport } from '../server/transport.js';

export interface OvhCredentials { applicationKey: string; applicationSecret: string; consumerKey: string }

export function ovhSignature(credentials: OvhCredentials, request: OutboundRequest, timestamp: number) {
  const body = request.body === undefined ? '' : typeof request.body === 'string' ? request.body : Buffer.from(request.body).toString('utf8');
  return '$1$' + createHash('sha1').update([credentials.applicationSecret, credentials.consumerKey,
    request.method ?? 'GET', request.url, body, String(timestamp)].join('+')).digest('hex');
}

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

}
