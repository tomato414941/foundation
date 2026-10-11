import { randomUUID } from 'node:crypto';
import { ConnectionMaterial } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { fail } from '../server/errors.js';
import type { AwsConnectionProvider } from './aws.js';
import type { AuthorizationContext, ConnectionProvider, ConnectionStart } from './connection-provider.js';

export class AwsConnection implements ConnectionProvider {
  constructor(readonly aws: AwsConnectionProvider) {}
  validate(input: ConnectionStart) {
    if (!input.aws) fail(400, 'aws_authentication_required', 'Choose AWS authentication for this executor.');
  }
  async start({ input, signal }: AuthorizationContext) {
    const aws = (await this.aws.obtain(input.aws!, undefined, signal)).state;
    return { kind: 'ready' as const, material: ConnectionMaterial.parse({ format: 2,
      methodId: input.methodId, method: input.method, generation: randomUUID(), appId: null, appGeneration: null,
      aws }) };
  }
  needsRenewal() { return false; }
  async check(value: ConnectionState, signal: AbortSignal) {
    await this.outputs(value, null, signal);
  }
  async outputs(value: ConnectionState, _app: AppState | null, signal: AbortSignal) {
    return (await this.aws.obtain(value.aws!, value.aws, signal)).credentials;
  }
}
