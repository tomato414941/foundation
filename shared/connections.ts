import { z } from 'zod';
import { AuthKind, Id, JsonObject, MethodDefinition, Name } from './contracts.js';
import { Fingerprint, hash } from './authority.js';
import { PolicyApproval } from './custody.js';
import { connectionMethod, requiresApp } from './connection-methods.js';
import { AwsConnectionInput, AwsConnectionMaterial, AwsConnectionInfo, awsConnectionInfo } from './aws.js';
import { connectionAuthorization, connectionAccount } from './connection-authorization.js';
export { requiresApp } from './connection-methods.js';

const Fields = z.record(z.string().max(100), z.string().max(16384));
export const AppMaterial = z.object({
  format: z.literal(1), methodId: z.string().min(1), generation: Id,
  clientId: z.string().max(1000), clientSecret: z.string().max(16384).optional(), fields: Fields,
}).strict();
export type AppState = z.infer<typeof AppMaterial>;
export const TokenMaterial = z.object({
  accessToken: z.string().min(1).max(16384), refreshToken: z.string().min(1).max(16384).optional(),
  expiresAt: z.number().nullable(), refreshExpiresAt: z.number().optional(), scopes: z.array(z.string()),
  requestedScopes: z.array(z.string()).optional(),
  account: z.string(), accountName: z.string(), accountVerified: z.boolean().optional(),
  scopesStatus: z.enum(['unknown', 'requested', 'reported']).optional(), extra: Fields, facts: JsonObject,
}).strict();
export const ConnectionMaterial = z.object({
  format: z.literal(1), methodId: z.string().min(1), method: MethodDefinition, generation: Id,
  authorizationVersion: z.literal(2).optional(),
  appId: Id.nullable(), appGeneration: Id.nullable(),
  state: z.literal('reconnect').optional(),
  oauth: TokenMaterial.optional(), fields: Fields.optional(),
  aws: AwsConnectionMaterial.optional(),
  role: z.object({ arn: z.string().regex(/^arn:aws(?:-us-gov|-cn)?:iam::\d{12}:role\/.+/),
    externalId: z.string().min(16).max(1000), region: z.string().regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/) }).strict().optional(),
}).strict().superRefine((value, ctx) => {
  if ((value.method.kind === 'oauth' && (!value.oauth || (requiresApp(value.method) && (!value.appId || !value.appGeneration)))) ||
    (value.method.kind === 'token' && !value.fields) || (value.method.kind === 'role' && !value.role && !value.aws))
    ctx.addIssue({ code: 'custom', message: 'Supply the material required by this connection method.' });
  if (value.aws && (value.method.kind !== 'role' || value.role))
    ctx.addIssue({ code: 'custom', message: 'Use one AWS authentication configuration for this connection.' });
  if (Boolean(value.appId) !== Boolean(value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the application and its generation together.' });
  if (value.authorizationVersion && !value.aws)
    ctx.addIssue({ code: 'custom', message: 'Use the AWS identity authorization with AWS connection material.' });
});
export type ConnectionState = z.infer<typeof ConnectionMaterial>;

export const AppMetadata = z.object({ methodId: z.string().min(1).max(200),
  clientId: z.string().max(1000), generation: Id }).strict();
// Signed with the encrypted content. Display names are not part of it: they travel as labels.
export const ConnectionMetadata = z.object({
  methodId: z.string().min(1).max(200), methodKind: AuthKind,
  generation: Id, authorizationDigest: Fingerprint, appId: Id.nullable(),
  accountId: z.string().max(2000).nullable(), accountVerified: z.boolean(),
  scopes: z.array(z.string().max(1000)).max(200), scopesStatus: z.enum(['unknown', 'requested', 'reported']),
  outputs: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)).max(100), state: z.enum(['ready', 'reconnect']),
  aws: AwsConnectionInfo.optional(),
}).strict();

export async function connectionMetadata(state: ConnectionState) {
  const outputs = [...connectionMethod(state.method).outputs, ...(state.aws ? ['AWS_REGION'] : [])];
  const authorizationDigest = await hash(connectionAuthorization(state));
  return ConnectionMetadata.parse({
    methodId: state.methodId, methodKind: state.method.kind,
    generation: state.generation, authorizationDigest, appId: state.appId,
    accountId: connectionAccount(state),
    accountVerified: Boolean(state.role || state.aws || state.oauth?.accountVerified),
    scopes: state.oauth?.scopes ?? [], scopesStatus: state.oauth?.scopesStatus ?? 'unknown',
    outputs, state: state.state ?? 'ready',
    ...(state.aws ? { aws: awsConnectionInfo(state.aws) } : {}),
  });
}

// What people read about a connection. The server stores these as given; they carry no authority.
export const ConnectionLabels = z.object({ methodName: Name, account: z.string().max(2000) }).strict();
export type ConnectionLabelValues = z.infer<typeof ConnectionLabels>;
export function connectionLabels(state: ConnectionState): ConnectionLabelValues {
  return { methodName: state.method.name, account: state.oauth?.accountName ?? state.role?.arn ??
    (state.aws ? state.aws.identity.accountId + ' / ' + state.aws.identity.arn.split(':').at(-1) : state.method.name) };
}

const FlowStart = z.object({
  action: z.literal('start'), flowId: Id, name: Name,
  methodId: z.string().min(1), method: MethodDefinition, appId: Id.nullable(),
  fields: Fields.default({}), scopes: z.array(z.string().max(1000)).max(200).default([]),
  requestedScopes: z.array(z.string().max(1000)).max(200).optional(),
  authorizationVersion: z.literal(2).optional(),
  redirectUri: z.url().optional(), role: ConnectionMaterial.shape.role,
  aws: AwsConnectionInput.optional(),
}).strict().superRefine((value, ctx) => {
  if (((value.aws || value.role) && connectionMethod(value.method).family !== 'aws') || (value.aws && value.role))
    ctx.addIssue({ code: 'custom', message: 'Choose one authentication configuration for this connection method.' });
  if (value.authorizationVersion && !value.aws)
    ctx.addIssue({ code: 'custom', message: 'Use the AWS identity authorization with AWS authentication.' });
});
export const ConnectionAction = z.discriminatedUnion('action', [
  FlowStart,
  z.object({ action: z.literal('exchange'), flowId: Id, parameters: z.string().max(16384) }).strict(),
  z.object({ action: z.literal('commit'), flowId: Id, authorizationDigest: Fingerprint, approval: PolicyApproval }).strict(),
  z.object({ action: z.literal('refresh'), id: Id }).strict(),
  z.object({ action: z.literal('revoke'), id: Id }).strict(),
]);
export type ConnectionCommand = z.infer<typeof ConnectionAction>;
