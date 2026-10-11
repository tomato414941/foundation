import type { ConnectionFamily } from '../shared/connection-methods.js';
import type { Transport } from '../server/transport.js';
import type { AwsConnectionProvider } from './aws.js';
import type { RoleProvider } from './roles.js';
import type { ConnectionProvider } from './connection-provider.js';
import { AwsConnection } from './aws-connection.js';
import { OAuthConnection } from './oauth-connection.js';
import { TokenConnection } from './token-connection.js';

export function connectionProviders(transport: Transport, roles: RoleProvider, aws: AwsConnectionProvider):
  Readonly<Record<ConnectionFamily, ConnectionProvider>> {
  return { oauth: new OAuthConnection(transport), token: new TokenConnection(), aws: new AwsConnection(aws, roles) };
}
