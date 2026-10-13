import { tokenConnectionFacts } from '../shared/connection-facts.js';
import type { ConnectionState } from '../shared/connections.js';
import { atPointer, textValue } from '../shared/values.js';
import { connectionValues } from '../shared/connection-fields.js';
import type { ConnectionProvider } from './connection-provider.js';

function specification(value: ConnectionState) {
  if (value.method.kind !== 'token' && value.method.kind !== 'approval') throw new Error('Use an input credential provider.');
  return value.method.config;
}
export class TokenConnection implements ConnectionProvider {
  facts = tokenConnectionFacts;
  needsRenewal() { return false; }
  async outputs(value: ConnectionState) {
    const spec = specification(value);
    const fields = connectionValues(spec.fields, value.fields!, 'constants' in spec ? spec.constants ?? {} : {});
    return Object.fromEntries(Object.entries(specification(value).outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(fields, pointer))]));
  }
}
