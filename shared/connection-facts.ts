import { z } from 'zod';
import { JsonObject } from './contracts.js';
import type { AuthKindName } from './contracts.js';
import type { ConnectionState } from './connections.js';
import { awsAuthorization, awsConnectionInfo, stableAwsArn } from './aws.js';

const commonFacts = new Set(['format', 'generation', 'methodId', 'method', 'appId', 'appGeneration', 'account',
  'accountId', 'accountName', 'accountVerified', 'scopes', 'scopesStatus', 'outputs', 'state', 'methodKind', 'authorizationDigest']);
const extensions = JsonObject.refine(value => Object.keys(value).every(key => !commonFacts.has(key)),
  'Keep method-specific facts separate from common facts.');

// Providers expose observations, not credentials. Readers use the same projection as executors.
export const ConnectionFacts = z.object({
  accountId: z.string().max(2000).nullable(), accountName: z.string().max(2000), accountVerified: z.boolean(),
  scopes: z.array(z.string().max(1000)).max(200), scopesStatus: z.enum(['unknown', 'requested', 'reported']),
  authorization: extensions, details: extensions,
}).strict();
export type ConnectionFactValues = z.infer<typeof ConnectionFacts>;

export function oauthConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'oauth' || !state.oauth) throw new Error('Use OAuth connection material.');
  return ConnectionFacts.parse({ accountId: state.oauth.account, accountName: state.oauth.accountName,
    accountVerified: state.oauth.accountVerified ?? false, scopes: state.oauth.scopes,
    scopesStatus: state.oauth.scopesStatus ?? 'unknown', authorization: {}, details: {} });
}
export function tokenConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'token' || !state.fields) throw new Error('Use token connection material.');
  return ConnectionFacts.parse({ accountId: null, accountName: state.method.name, accountVerified: false,
    scopes: [], scopesStatus: 'unknown', authorization: {}, details: {} });
}
export function awsConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'aws' || !state.aws) throw new Error('Use AWS connection material.');
  return ConnectionFacts.parse({ accountId: stableAwsArn(state.aws.identity.arn),
    accountName: state.aws.identity.accountId + ' / ' + state.aws.identity.arn.split(':').at(-1), accountVerified: true,
    scopes: [], scopesStatus: 'unknown', authorization: { aws: awsAuthorization(state.aws) },
    details: { aws: awsConnectionInfo(state.aws) } });
}
const projections: Record<AuthKindName, (state: ConnectionState) => ConnectionFactValues> = {
  oauth: oauthConnectionFacts, token: tokenConnectionFacts, aws: awsConnectionFacts,
};
export function connectionFacts(state: ConnectionState): ConnectionFactValues { return projections[state.method.kind](state); }
