import { randomUUID } from 'node:crypto';
import { Template } from '@fedify/uri-template';
import { z } from 'zod';
import { canonical } from '../shared/authority.js';
import { ConnectionMaterial } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { ovhConnectionFacts } from '../shared/connection-facts.js';
import { connectionValues } from '../shared/connection-fields.js';
import { selectScopes } from '../shared/connection-methods.js';
import { ovhAccessRules } from '../shared/ovh.js';
import { textValue, atPointer } from '../shared/values.js';
import { fail } from '../server/errors.js';
import { publicUrl, responseJson } from '../server/transport.js';
import type { Transport } from '../server/transport.js';
import type { AuthorizationContext, ConnectionCheckpoint, ConnectionProvider, ConnectionStart } from './connection-provider.js';
import { OvhApi } from './ovh.js';
import type { OvhCredentials } from './ovh.js';

function specification(value: ConnectionStart | ConnectionState) {
  if (value.method.kind !== 'ovh') throw new Error('Use an OVH connection provider.');
  return value.method.config;
}
const pending = z.object({ consumerKey: z.string().min(1).max(16384), validationUrl: z.url() });

export class OvhConnection implements ConnectionProvider {
  facts = ovhConnectionFacts;
  private readonly api: OvhApi;
  constructor(readonly transport: Transport) { this.api = new OvhApi(transport); }

  private values(input: ConnectionStart | ConnectionState, app: AppState | null) {
    const spec = specification(input), browser = spec.authorization === 'consumer_key';
    if (browser && (!app?.clientId || !app.clientSecret)) fail(409, 'app_required', 'Choose an OVHcloud API application with its key and secret.');
    const fields = browser ? app!.fields : input.fields!;
    return connectionValues(spec.fields, fields);
  }
  private base(input: ConnectionStart | ConnectionState, app: AppState | null) {
    return new Template(specification(input).apiBaseUrl).expand(this.values(input, app)).replace(/\/$/, '');
  }
  private credentials(input: ConnectionStart | ConnectionState, app: AppState | null): OvhCredentials {
    if (specification(input).authorization === 'consumer_key') return {
      applicationKey: app!.clientId, applicationSecret: app!.clientSecret!, consumerKey: input.fields!.consumerKey!,
    };
    const fields = this.values(input, app);
    return { applicationKey: fields.applicationKey!, applicationSecret: fields.applicationSecret!, consumerKey: fields.consumerKey! };
  }
  validate(input: ConnectionStart, app: AppState | null) {
    const spec = specification(input);
    this.values(input, app);
    if (spec.authorization === 'consumer_key') {
      for (const [key, value] of Object.entries(input.fields)) if (value && app!.fields[key] !== value)
        fail(409, 'wrong_app', 'Choose an application with the approved service settings.');
      try { ovhAccessRules(selectScopes(spec.scopes, input.scopes)); }
      catch { fail(400, 'invalid_scope', 'Use one HTTP method and API path for each OVH permission.'); }
    }
  }
  async start(context: AuthorizationContext) {
    const { input, app, signal } = context, spec = specification(input);
    if (spec.authorization === 'api_key') return { kind: 'ready' as const, material: await this.material(input, app, input.fields, signal) };
    const redirection = new URL(input.redirectUri!);
    redirection.searchParams.set('state', context.state);
    await context.dispatch();
    const response = await this.transport.send({ url: this.base(input, app) + '/auth/credential', method: 'POST', signal,
      headers: { 'Content-Type': 'application/json', 'X-Ovh-Application': app!.clientId },
      body: JSON.stringify({ redirection: redirection.href, accessRules: ovhAccessRules(selectScopes(spec.scopes, input.scopes)) }) });
    if (response.status >= 400) fail(400, 'invalid_credentials', 'Check the OVHcloud application key and account region.');
    const checkpoint = pending.safeParse(responseJson(response));
    if (!checkpoint.success) fail(502, 'invalid_response', 'OVHcloud returned an invalid authorization request.');
    const url = publicUrl(checkpoint.data.validationUrl);
    if (!['ovh.com', 'ovhcloud.com'].some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain)))
      fail(502, 'invalid_response', 'OVHcloud returned an unexpected authorization address.');
    await context.receive(checkpoint.data);
    return { kind: 'authorize' as const, url: checkpoint.data.validationUrl };
  }
  async resume(_context: AuthorizationContext, checkpoint: ConnectionCheckpoint) {
    return { kind: 'authorize' as const, url: pending.parse(checkpoint).validationUrl };
  }
  async exchange(context: AuthorizationContext, parameters: string, checkpoint?: ConnectionCheckpoint) {
    const query = new URLSearchParams(parameters);
    if (query.getAll('state').length !== 1 || query.get('state') !== context.state)
      fail(400, 'invalid_state', 'Start the connection again.');
    if (!checkpoint) fail(409, 'connection_uncertain', 'Start the OVHcloud connection again.');
    const saved = pending.parse(checkpoint);
    return this.material(context.input, context.app, { ...context.input.fields, consumerKey: saved.consumerKey }, context.signal);
  }
  private async material(input: ConnectionStart, app: AppState | null, fields: Record<string, string>, signal: AbortSignal) {
    const value = { ...input, fields }, info = await this.api.inspect(this.base(input, app), this.credentials(value, app), signal);
    return ConnectionMaterial.parse({ format: 2, methodId: input.methodId, method: input.method,
      generation: randomUUID(), appId: input.appId, appGeneration: input.appId ? app!.generation : null, fields, ovh: info });
  }
  needsRenewal() { return false; }
  async check(value: ConnectionState, signal: AbortSignal, app: AppState | null) {
    const current = await this.api.inspect(this.base(value, app), this.credentials(value, app), signal);
    if (value.method.kind !== 'ovh' || !('ovh' in value) || canonical(current) !== canonical(value.ovh))
      fail(409, 'connection_changed', 'Reconnect OVHcloud to approve its current account and API permissions.');
  }
  async outputs(value: ConnectionState, app: AppState | null) {
    if (value.method.kind !== 'ovh' || !('ovh' in value)) throw new Error('Use OVH connection material.');
    if (value.ovh.expiresAt !== null && value.ovh.expiresAt <= Date.now())
      fail(409, 'reconnect_required', 'Reconnect OVHcloud with a current API key.');
    const fields = specification(value).authorization === 'consumer_key'
      ? { ...this.values(value, app), ...this.credentials(value, app) } : this.values(value, app);
    return Object.fromEntries(Object.entries(specification(value).outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(fields, pointer))]));
  }
}
