import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import { DomainError, fail } from '../server/errors.js';
import { AwsPrincipal } from '../shared/execution.js';

export interface RoleCredentials extends Record<string, string> {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
  AWS_DEFAULT_REGION: string;
}
export interface RoleProvider {
  obtain(arn: string, externalId: string, region: string): Promise<RoleCredentials>;
}

// Only a complete IAM ARN can identify the principal a trust policy should name.
export function awsPrincipal(callerArn: string): string | null {
  return AwsPrincipal.safeParse(callerArn).success ? callerArn : null;
}

// Which AWS identity this process runs as, if any, found the way the SDK finds credentials. Nothing to find is
// the usual case on a machine outside AWS, so that answers quickly rather than failing.
export async function detectAwsPrincipal(timeoutMs = 3000): Promise<string | null> {
  const sts = new STSClient({ region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1' });
  let iam: IAMClient | undefined;
  const abortSignal = AbortSignal.timeout(timeoutMs);
  try {
    const identity = await sts.send(new GetCallerIdentityCommand({}), { abortSignal });
    if (!identity.Arn) return null;
    const principal = awsPrincipal(identity.Arn);
    if (principal) return principal;
    const assumed = /^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role\/([^/]+)\/.+$/.exec(identity.Arn);
    if (!assumed || identity.Account !== assumed[2] || !identity.UserId) return null;
    // STS omits the role's path. Resolve it with the same credential provider and verify its immutable ID.
    iam = new IAMClient({ region: sts.config.region, credentials: sts.config.credentials });
    const response = await iam.send(new GetRoleCommand({ RoleName: assumed[3] }), { abortSignal });
    const role = response.Role;
    if (!role?.Arn || role.RoleId !== identity.UserId.split(':')[0]) return null;
    const arn = awsPrincipal(role.Arn);
    return arn?.startsWith(`arn:${assumed[1]}:iam::${assumed[2]}:role/`) && arn.split('/').at(-1) === assumed[3]
      ? arn : null;
  } catch {
    return null;
  } finally { sts.destroy(); iam?.destroy(); }
}

// Credentials come from this executor's workload identity, never the control plane.
export class AwsRoles implements RoleProvider {
  async obtain(arn: string, externalId: string, region: string) {
    const sts = new STSClient({ region });
    try {
      const response = await sts.send(new AssumeRoleCommand({ RoleArn: arn,
        RoleSessionName: 'foundation-' + randomUUID().slice(0, 8), ExternalId: externalId, DurationSeconds: 3600 }));
      const key = response.Credentials;
      if (!key?.AccessKeyId || !key.SecretAccessKey || !key.SessionToken)
        fail(502, 'invalid_response', 'AWS did not return credentials.');
      const client = new STSClient({ region, credentials: {
        accessKeyId: key.AccessKeyId, secretAccessKey: key.SecretAccessKey, sessionToken: key.SessionToken,
      } });
      try {
        const identity = await client.send(new GetCallerIdentityCommand({}));
        if (identity.Account !== arn.split(':')[4])
          fail(502, 'account_changed', 'The AWS account could not be verified.');
      } finally { client.destroy(); }
      return { AWS_ACCESS_KEY_ID: key.AccessKeyId, AWS_SECRET_ACCESS_KEY: key.SecretAccessKey,
        AWS_SESSION_TOKEN: key.SessionToken, AWS_DEFAULT_REGION: region };
    } catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'role_denied', 'Check the IAM role and its trust policy for this executor.');
    } finally { sts.destroy(); }
  }
}
