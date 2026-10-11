import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import { AwsPrincipal } from '../shared/execution.js';

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
