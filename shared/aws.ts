import { z } from 'zod';

export const AwsRegion = z.string().regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/);
export const AwsRoleArn = z.string().max(2000).regex(/^arn:aws(?:-us-gov|-cn)?:iam::\d{12}:role\/.+/);
const accessKeyId = z.string().min(1).max(128);
const secretAccessKey = z.string().min(1).max(16384);
export const AwsAuthentication = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('access_key'), accessKeyId, secretAccessKey }).strict(),
  z.object({ kind: z.literal('session'), accessKeyId, secretAccessKey,
    sessionToken: z.string().min(1).max(16384), expiresAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER) }).strict(),
  z.object({ kind: z.literal('environment') }).strict(),
]);
export const AwsRoleOptions = z.object({ arn: AwsRoleArn,
  externalId: z.string().min(2).max(1224).regex(/^[\w+=,.@:\/-]+$/).optional() }).strict();
export const AwsConnectionInput = z.object({ authentication: AwsAuthentication,
  region: AwsRegion, role: AwsRoleOptions.optional() }).strict();
export type AwsConnectionRequest = z.infer<typeof AwsConnectionInput>;
export const AwsIdentity = z.object({ accountId: z.string().regex(/^\d{12}$/),
  principalId: z.string().min(1).max(256),
  arn: z.string().max(2000).regex(/^arn:aws(?:-us-gov|-cn)?:(?:iam|sts)::\d{12}:.+/) }).strict();
export type VerifiedAwsIdentity = z.infer<typeof AwsIdentity>;
export const AwsConnectionMaterial = AwsConnectionInput.extend({
  sourceIdentity: AwsIdentity, identity: AwsIdentity,
}).strict();
export type AwsConnectionState = z.infer<typeof AwsConnectionMaterial>;

export function stableAwsArn(arn: string) {
  return arn.includes(':assumed-role/') ? arn.slice(0, arn.lastIndexOf('/')) : arn;
}
function identityAuthorization(identity: VerifiedAwsIdentity) {
  return { ...identity, arn: stableAwsArn(identity.arn) };
}
export function awsAuthorization(state: AwsConnectionState) {
  return { authentication: state.authentication.kind, region: state.region, role: state.role ?? null,
    sourceIdentity: identityAuthorization(state.sourceIdentity), identity: identityAuthorization(state.identity) };
}

export const AwsConnectionInfo = z.object({ authentication: z.enum(['access_key', 'session', 'environment']),
  region: AwsRegion, sourceAccountId: z.string().regex(/^\d{12}$/), sourceArn: z.string().max(2000),
  roleArn: AwsRoleArn.optional(), expiresAt: z.number().int().positive().optional() }).strict();

export function awsConnectionInfo(state: AwsConnectionState): z.infer<typeof AwsConnectionInfo> {
  return { authentication: state.authentication.kind, region: state.region,
    sourceAccountId: state.sourceIdentity.accountId, sourceArn: state.sourceIdentity.arn,
    ...(state.role ? { roleArn: state.role.arn } : {}),
    ...(state.authentication.kind === 'session' ? { expiresAt: state.authentication.expiresAt } : {}),
  };
}
