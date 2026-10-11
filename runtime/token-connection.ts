import { randomUUID } from 'node:crypto';
import { ConnectionMaterial } from '../shared/connections.js';
import type { ConnectionState } from '../shared/connections.js';
import { atPointer, textValue } from '../shared/values.js';
import { connectionFields } from './connection-fields.js';
import type { AuthorizationContext, ConnectionProvider, ConnectionStart } from './connection-provider.js';

function specification(value: ConnectionStart | ConnectionState) {
  if (value.method.kind !== 'token') throw new Error('Use a token connection provider.');
  return value.method.config;
}
export class TokenConnection implements ConnectionProvider {
  validate(input: ConnectionStart) {
    connectionFields(specification(input).fields, input.fields);
  }
  async start({ input }: AuthorizationContext) {
    return { kind: 'ready' as const, material: ConnectionMaterial.parse({ format: 2,
      methodId: input.methodId, method: input.method, generation: randomUUID(), appId: null, appGeneration: null,
      fields: connectionFields(specification(input).fields, input.fields) }) };
  }
  needsRenewal() { return false; }
  async outputs(value: ConnectionState) {
    return Object.fromEntries(Object.entries(specification(value).outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(value.fields!, pointer))]));
  }
}
