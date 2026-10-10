import { z } from 'zod';
import { AuthKind, Id, JsonObject, MethodDefinition, Name } from './contracts.js';
import { Fingerprint, hash } from './authority.js';
import { PolicyApproval } from './custody.js';
import { connectionMethod, requiresApp } from './connection-methods.js';
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
  appId: Id.nullable(), appGeneration: Id.nullable(),
  state: z.literal('reconnect').optional(),
  oauth: TokenMaterial.optional(), fields: Fields.optional(),
  role: z.object({ arn: z.string().regex(/^arn:aws(?:-us-gov|-cn)?:iam::\d{12}:role\/.+/),
    externalId: z.string().min(16).max(1000), region: z.string().regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/) }).strict().optional(),
}).strict().superRefine((value, ctx) => {
  if ((value.method.kind === 'oauth' && (!value.oauth || (requiresApp(value.method) && (!value.appId || !value.appGeneration)))) ||
    (value.method.kind === 'token' && !value.fields) || (value.method.kind === 'role' && !value.role))
    ctx.addIssue({ code: 'custom', message: 'Supply the material required by this connection method.' });
  if (Boolean(value.appId) !== Boolean(value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the application and its generation together.' });
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
}).strict();

export async function connectionMetadata(state: ConnectionState) {
  const outputs = connectionMethod(state.method).outputs;
  const authorizationDigest = await hash({
    generation: state.generation, methodId: state.methodId, method: state.method,
    appId: state.appId, appGeneration: state.appGeneration,
    account: state.oauth?.account ?? state.role?.arn ?? null,
    accountVerified: state.oauth?.accountVerified ?? false,
    scopes: [...(state.oauth?.scopes ?? [])].sort(), role: state.role ?? null,
    ...(state.state ? { state: state.state } : {}),
  });
  return ConnectionMetadata.parse({
    methodId: state.methodId, methodKind: state.method.kind,
    generation: state.generation, authorizationDigest, appId: state.appId,
    accountId: state.role?.arn ?? (state.oauth?.accountVerified ? state.oauth.account : null),
    accountVerified: Boolean(state.role || state.oauth?.accountVerified),
    scopes: state.oauth?.scopes ?? [], scopesStatus: state.oauth?.scopesStatus ?? 'unknown',
    outputs, state: state.state ?? 'ready',
  });
}

// What people read about a connection. The server stores these as given; they carry no authority.
export const ConnectionLabels = z.object({ methodName: Name, account: z.string().max(2000) }).strict();
export type ConnectionLabelValues = z.infer<typeof ConnectionLabels>;
export function connectionLabels(state: ConnectionState): ConnectionLabelValues {
  return { methodName: state.method.name, account: state.oauth?.accountName ?? state.role?.arn ?? state.method.name };
}

const FlowStart = z.object({
  action: z.literal('start'), flowId: Id, name: Name,
  methodId: z.string().min(1), method: MethodDefinition, appId: Id.nullable(),
  fields: Fields.default({}), scopes: z.array(z.string().max(1000)).max(200).default([]),
  redirectUri: z.url().optional(), role: ConnectionMaterial.shape.role,
}).strict();
export const ConnectionAction = z.discriminatedUnion('action', [
  FlowStart,
  z.object({ action: z.literal('exchange'), flowId: Id, parameters: z.string().max(16384) }).strict(),
  z.object({ action: z.literal('commit'), flowId: Id, authorizationDigest: Fingerprint, approval: PolicyApproval }).strict(),
  z.object({ action: z.literal('refresh'), id: Id }).strict(),
  z.object({ action: z.literal('revoke'), id: Id }).strict(),
]);
export type ConnectionCommand = z.infer<typeof ConnectionAction>;
