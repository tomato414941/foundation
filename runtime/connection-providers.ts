import type { ConnectionFamily } from '../shared/connection-methods.js';
import type { Transport } from '../server/transport.js';
import type { AwsConnectionProvider } from './aws.js';
import type { ConnectionProvider } from './connection-provider.js';
import { AwsConnection } from './aws-connection.js';
import { OAuthConnection } from './oauth-connection.js';
import { TokenConnection } from './token-connection.js';
import { OvhConnection } from './ovh-connection.js';
import type { MethodDescription } from '../shared/contracts.js';
import { VultrRoleConnection } from './vultr-role-connection.js';

export function connectionProviders(transport: Transport, aws: AwsConnectionProvider):
  (method: MethodDescription) => ConnectionProvider {
  const providers: Readonly<Record<ConnectionFamily, ConnectionProvider>> = {
    oauth: new OAuthConnection(transport), token: new TokenConnection(), aws: new AwsConnection(aws),
    approval: new TokenConnection(),
    ovh: new OvhConnection() };
  const role = new VultrRoleConnection(transport);
  return method => method.kind === 'token' && method.config.resolver === 'vultr-role'
    ? role : providers[method.kind];
}
