import type { AppState, ConnectionState } from '../shared/connections.js';
import { ovhConnectionFacts } from '../shared/connection-facts.js';
import { connectionValues } from '../shared/connection-fields.js';
import { textValue, atPointer } from '../shared/values.js';
import { fail } from '../server/errors.js';
import type { ConnectionProvider } from './connection-provider.js';
import type { OvhCredentials } from './ovh.js';

function specification(value: ConnectionState) {
  if (value.method.kind !== 'ovh') throw new Error('Use an OVH connection provider.');
  return value.method.config;
}
export class OvhConnection implements ConnectionProvider {
  facts = ovhConnectionFacts;

  private values(input: ConnectionState, app: AppState | null) {
    const spec = specification(input), browser = spec.authorization === 'consumer_key';
    if (browser && (!app?.clientId || !app.clientSecret)) fail(409, 'app_required', 'Choose an OVHcloud API application with its key and secret.');
    const fields = browser ? app!.fields : input.fields!;
    return connectionValues(spec.fields, fields);
  }
  private credentials(input: ConnectionState, app: AppState | null): OvhCredentials {
    if (specification(input).authorization === 'consumer_key') return {
      applicationKey: app!.clientId, applicationSecret: app!.clientSecret!, consumerKey: input.fields!.consumerKey!,
    };
    const fields = this.values(input, app);
    return { applicationKey: fields.applicationKey!, applicationSecret: fields.applicationSecret!, consumerKey: fields.consumerKey! };
  }
  needsRenewal() { return false; }
  async outputs(value: ConnectionState, app: AppState | null) {
    if (value.method.kind !== 'ovh') throw new Error('Use OVH connection material.');
    const info = 'ovh' in value ? value.ovh : undefined;
    if (info && info.expiresAt !== null && info.expiresAt <= Date.now())
      fail(409, 'reconnect_required', 'Reconnect OVHcloud with a current API key.');
    const fields = specification(value).authorization === 'consumer_key'
      ? { ...this.values(value, app), ...this.credentials(value, app) } : this.values(value, app);
    return Object.fromEntries(Object.entries(specification(value).outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(fields, pointer))]));
  }
}
