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
  if (state.method.kind !== 'oauth') throw new Error('Use OAuth connection material.');
  const requestedScopes = 'requestedScopes' in state ? state.requestedScopes : undefined;
  return ConnectionFacts.parse({ accountId: state.oauth?.account ?? '', accountName: state.oauth?.accountName ?? '',
    accountVerified: state.oauth?.accountVerified ?? false, scopes: requestedScopes ?? state.oauth?.scopes ?? [],
    scopesStatus: requestedScopes ? 'requested' : state.oauth?.scopesStatus ?? 'unknown', authorization: {}, details: {} });
}
export function tokenConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'token' || !state.fields) throw new Error('Use token connection material.');
  if ('facts' in state && state.facts) return ConnectionFacts.parse(state.facts);
  return ConnectionFacts.parse({ accountId: null, accountName: state.method.name, accountVerified: false,
    scopes: [], scopesStatus: 'unknown', authorization: {}, details: {} });
}
export function ovhConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'ovh') throw new Error('Use OVH connection material.');
  const info = 'ovh' in state ? state.ovh : undefined;
  if (!info) {
    const scopes = 'requestedScopes' in state ? state.requestedScopes : undefined;
    return ConnectionFacts.parse({ accountId: null, accountName: '', accountVerified: false,
      scopes: scopes ?? [], scopesStatus: scopes ? 'requested' : 'unknown', authorization: {}, details: {} });
  }
  return ConnectionFacts.parse({ accountId: info.user ? info.account + '/' + info.user : info.account,
    accountName: info.account + (info.user ? ' / ' + info.user : ''), accountVerified: true,
    scopes: info.rules.map(rule => rule.method + ' ' + rule.path),
    scopesStatus: 'reported', authorization: { ovh: info }, details: { ovh: info } });
}
export function awsConnectionFacts(state: ConnectionState): ConnectionFactValues {
  if (state.method.kind !== 'aws' || !state.aws) throw new Error('Use AWS connection material.');
  return ConnectionFacts.parse({ accountId: state.aws.identity ? stableAwsArn(state.aws.identity.arn) : null,
    accountName: state.aws.identity ? state.aws.identity.accountId + ' / ' + state.aws.identity.arn.split(':').at(-1) : '', accountVerified: Boolean(state.aws.identity),
    scopes: [], scopesStatus: 'unknown', authorization: { aws: awsAuthorization(state.aws) },
    details: { aws: awsConnectionInfo(state.aws) } });
}
const projections: Record<AuthKindName, (state: ConnectionState) => ConnectionFactValues> = {
  oauth: oauthConnectionFacts, token: tokenConnectionFacts, aws: awsConnectionFacts, ovh: ovhConnectionFacts,
};
export function connectionFacts(state: ConnectionState): ConnectionFactValues { return projections[state.method.kind](state); }
