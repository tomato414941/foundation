import type { ConnectionState } from './connections.js';
import { awsAuthorization, stableAwsArn } from './aws.js';

export function connectionAccount(state: ConnectionState) {
  return state.aws ? stableAwsArn(state.aws.identity.arn) : (state.oauth?.accountVerified ? state.oauth.account : null);
}

export function connectionAuthorization(state: ConnectionState) {
  return {
    format: state.format,
    generation: state.generation, methodId: state.methodId, method: state.method,
    appId: state.appId, appGeneration: state.appGeneration,
    account: state.oauth?.account ?? connectionAccount(state),
    accountVerified: state.aws ? true : state.oauth?.accountVerified ?? false,
    scopes: [...(state.oauth?.scopes ?? [])].sort(),
    ...(state.aws ? { aws: awsAuthorization(state.aws) } : {}),
    ...(state.state ? { state: state.state } : {}),
  };
}
