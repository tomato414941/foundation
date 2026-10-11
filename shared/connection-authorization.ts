import type { ConnectionState } from './connections.js';
import { awsAuthorization, stableAwsArn } from './aws.js';

export function connectionAccount(state: ConnectionState) {
  if (state.authorizationVersion === 2) return stableAwsArn(state.aws!.identity.arn);
  return state.role?.arn ?? state.aws?.identity.arn ?? (state.oauth?.accountVerified ? state.oauth.account : null);
}

export function connectionAuthorization(state: ConnectionState) {
  const authorization = {
    generation: state.generation, methodId: state.methodId, method: state.method,
    appId: state.appId, appGeneration: state.appGeneration,
    account: state.oauth?.account ?? state.role?.arn ?? state.aws?.identity.arn ?? null,
    accountVerified: state.aws ? true : state.oauth?.accountVerified ?? false,
    scopes: [...(state.oauth?.scopes ?? [])].sort(), role: state.role ?? null,
    ...(state.state ? { state: state.state } : {}),
  };
  if (state.authorizationVersion === 2) return { ...authorization, authorizationVersion: 2,
    account: connectionAccount(state), aws: awsAuthorization(state.aws!) };
  // Existing signatures include the complete AWS source material and must keep their original digest.
  return { ...authorization, ...(state.aws ? { aws: state.aws } : {}) };
}
