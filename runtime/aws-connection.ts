import { awsConnectionFacts } from '../shared/connection-facts.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import type { AwsConnectionProvider } from './aws.js';
import type { ConnectionProvider } from './connection-provider.js';

export class AwsConnection implements ConnectionProvider {
  facts = awsConnectionFacts;
  constructor(readonly aws: AwsConnectionProvider) {}
  needsRenewal() { return false; }
  async outputs(value: ConnectionState, _app: AppState | null, signal: AbortSignal) {
    return (await this.aws.obtain(value.aws!, value.aws, signal)).credentials;
  }
}
