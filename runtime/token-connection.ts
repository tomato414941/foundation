import { randomUUID } from 'node:crypto';
import { Template } from '@fedify/uri-template';
import { ConnectionMaterial } from '../shared/connections.js';
import { tokenConnectionFacts } from '../shared/connection-facts.js';
import type { ConnectionState } from '../shared/connections.js';
import { ConnectionFacts } from '../shared/connection-facts.js';
import { fail } from '../server/errors.js';
import { responseJson } from '../server/transport.js';
import type { Transport } from '../server/transport.js';
import { atPointer, textValue } from '../shared/values.js';
import { connectionFields } from './connection-fields.js';
import { connectionValues } from '../shared/connection-fields.js';
import type { AuthorizationContext, ConnectionProvider, ConnectionStart } from './connection-provider.js';

function specification(value: ConnectionStart | ConnectionState) {
  if (value.method.kind !== 'token') throw new Error('Use a token connection provider.');
  return value.method.config;
}
export class TokenConnection implements ConnectionProvider {
  facts = tokenConnectionFacts;
  constructor(readonly transport: Transport) {}
  validate(input: ConnectionStart) {
    connectionFields(specification(input).fields, input.fields);
  }
  private async inspect(value: ConnectionStart | ConnectionState, signal: AbortSignal) {
    const spec = specification(value), identity = spec.identity;
    if (!identity) return undefined;
    const fields = connectionValues(spec.fields, value.fields!);
    const response = await this.transport.send({ url: new Template(identity.url).expand(fields), signal,
      headers: Object.fromEntries(Object.entries(identity.headers).map(([key, value]) => [key,
        value.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
          if (!Object.hasOwn(fields, name)) fail(400, 'missing_field', 'Complete the required service fields.');
          return fields[name]!;
        })])) });
    if (response.status === 401 || response.status === 403)
      fail(400, 'invalid_credentials', 'Check the access token, account region, and API permissions.');
    if (response.status !== 200) fail(502, 'service_response', 'The service could not confirm this connection.');
    const body = responseJson(response);
    const read = (pointer: string | string[]) => (Array.isArray(pointer) ? pointer : [pointer])
      .map(pointer => atPointer(body, pointer)).find(value => typeof value === 'string' && value.length > 0);
    const id = read(identity.id), name = read(identity.name);
    if (typeof id !== 'string' || typeof name !== 'string') fail(502, 'invalid_response', 'The service returned invalid account details.');
    return ConnectionFacts.parse({ accountId: id, accountName: name, accountVerified: true,
      scopes: [], scopesStatus: 'unknown', authorization: {}, details: {} });
  }
  async start({ input, signal }: AuthorizationContext) {
    const facts = await this.inspect(input, signal);
    return { kind: 'ready' as const, material: ConnectionMaterial.parse({ format: 2,
      methodId: input.methodId, method: input.method, generation: randomUUID(), appId: null, appGeneration: null,
      fields: connectionFields(specification(input).fields, input.fields), ...(facts ? { facts } : {}) }) };
  }
  async check(value: ConnectionState, signal: AbortSignal) {
    const facts = await this.inspect(value, signal);
    if (facts && facts.accountId !== this.facts(value).accountId)
      fail(409, 'connection_changed', 'Reconnect to approve the current service account.');
  }
  needsRenewal() { return false; }
  async outputs(value: ConnectionState) {
    const fields = connectionValues(specification(value).fields, value.fields!);
    return Object.fromEntries(Object.entries(specification(value).outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(fields, pointer))]));
  }
}
