import { randomUUID } from 'node:crypto';
import { ConnectionMaterial } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { fail } from '../server/errors.js';
import type { AwsConnectionProvider } from './aws.js';
import type { RoleProvider } from './roles.js';
import type { AuthorizationContext, ConnectionProvider, ConnectionStart } from './connection-provider.js';

export class AwsConnection implements ConnectionProvider {
  constructor(readonly aws: AwsConnectionProvider, readonly legacy: RoleProvider) {}
  validate(input: ConnectionStart) {
    if (!input.role && !input.aws) fail(400, 'role_required', 'Choose AWS authentication or a role trusted for this executor.');
  }
  async start({ input, signal }: AuthorizationContext) {
    const aws = input.aws ? (await this.aws.obtain(input.aws, undefined, signal)).state : undefined;
    if (!aws) await this.legacy.obtain(input.role!.arn, input.role!.externalId, input.role!.region);
    return { kind: 'ready' as const, material: ConnectionMaterial.parse({ format: 1,
      methodId: input.methodId, method: input.method, generation: randomUUID(), appId: null, appGeneration: null,
      ...(aws ? { aws, ...(input.authorizationVersion ? { authorizationVersion: input.authorizationVersion } : {}) }
        : { role: input.role }) }) };
  }
  needsRenewal() { return false; }
  async check(value: ConnectionState, signal: AbortSignal) {
    await this.outputs(value, null, signal);
  }
  async outputs(value: ConnectionState, _app: AppState | null, signal: AbortSignal) {
    return value.aws ? (await this.aws.obtain(value.aws, value.aws, signal)).credentials
      : this.legacy.obtain(value.role!.arn, value.role!.externalId, value.role!.region);
  }
}
