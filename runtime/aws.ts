import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import type { GetCallerIdentityCommandOutput } from '@aws-sdk/client-sts';
import { AwsConnectionInput, AwsConnectionMaterial, AwsIdentity, stableAwsArn } from '../shared/aws.js';
import type { AwsConnectionRequest, AwsConnectionState, VerifiedAwsIdentity } from '../shared/aws.js';
import { DomainError, fail } from '../server/errors.js';
import type { RoleCredentials } from './roles.js';

export interface AwsConnectionProvider {
  obtain(input: AwsConnectionRequest, expected?: AwsConnectionState, signal?: AbortSignal):
    Promise<{ credentials: RoleCredentials & { AWS_REGION: string }; state: AwsConnectionState }>;
}
function identity(value: GetCallerIdentityCommandOutput): VerifiedAwsIdentity {
  const parsed = AwsIdentity.safeParse({ accountId: value.Account, arn: value.Arn,
    principalId: value.Arn?.includes(':assumed-role/') ? value.UserId?.split(':')[0] : value.UserId });
  if (!parsed.success || parsed.data.arn.split(':')[4] !== parsed.data.accountId)
    fail(502, 'invalid_response', 'The AWS account could not be verified.');
  return parsed.data;
}
function sameIdentity(actual: VerifiedAwsIdentity, expected: VerifiedAwsIdentity) {
  return actual.accountId === expected.accountId && actual.principalId === expected.principalId &&
    stableAwsArn(actual.arn) === stableAwsArn(expected.arn);
}
function checkExpiry(expiration?: Date) {
  if (expiration && (!Number.isFinite(expiration.getTime()) || expiration.getTime() <= Date.now()))
    fail(409, 'reconnect_required', 'Reconnect with current AWS credentials.');
}

export class AwsConnections implements AwsConnectionProvider {
  async obtain(value: AwsConnectionRequest, expected?: AwsConnectionState, signal?: AbortSignal) {
    const input = AwsConnectionInput.parse({ authentication: value.authentication, region: value.region,
      ...(value.role ? { role: value.role } : {}) }), authentication = input.authentication;
    const configured = authentication.kind === 'environment' ? undefined : {
      accessKeyId: authentication.accessKeyId, secretAccessKey: authentication.secretAccessKey,
      ...(authentication.kind === 'session' ? {
        sessionToken: authentication.sessionToken, expiration: new Date(authentication.expiresAt),
      } : {}),
    };
    checkExpiry(configured?.expiration);
    const client = new STSClient({ region: input.region, ...(configured ? { credentials: configured } : {}) });
    let target: STSClient | undefined;
    const abortSignal = AbortSignal.any([AbortSignal.timeout(20_000), ...(signal ? [signal] : [])]);
    let assuming = false;
    try {
      // Freeze this attempt's source credentials so identity inspection and AssumeRole use the same source.
      const sourceCredentials = configured ?? await client.config.credentials();
      checkExpiry(sourceCredentials.expiration);
      target = new STSClient({ region: input.region, credentials: sourceCredentials });
      const sourceIdentity = identity(await target.send(new GetCallerIdentityCommand({}), { abortSignal }));
      if (expected && !sameIdentity(sourceIdentity, expected.sourceIdentity))
        fail(409, 'account_changed', 'Reconnect to approve the current AWS authentication source.');
      let credentials = sourceCredentials, effectiveIdentity = sourceIdentity;
      if (input.role) {
        assuming = true;
        const response = await target.send(new AssumeRoleCommand({ RoleArn: input.role.arn,
          RoleSessionName: 'foundation-' + randomUUID().slice(0, 8), DurationSeconds: 3600,
          ...(input.role.externalId ? { ExternalId: input.role.externalId } : {}),
        }), { abortSignal });
        const key = response.Credentials;
        if (!key?.AccessKeyId || !key.SecretAccessKey || !key.SessionToken || !key.Expiration)
          fail(502, 'invalid_response', 'AWS did not return credentials.');
        credentials = { accessKeyId: key.AccessKeyId, secretAccessKey: key.SecretAccessKey,
          sessionToken: key.SessionToken, expiration: key.Expiration };
        checkExpiry(credentials.expiration);
        target.destroy();
        target = new STSClient({ region: input.region, credentials });
        effectiveIdentity = identity(await target.send(new GetCallerIdentityCommand({}), { abortSignal }));
        const arn = input.role.arn.split(':');
        if (effectiveIdentity.accountId !== arn[4] || effectiveIdentity.arn.split(':')[1] !== arn[1] ||
          effectiveIdentity.arn.split(':')[5]?.split('/').slice(0, 2).join('/') !==
            'assumed-role/' + input.role.arn.split('/').at(-1))
          fail(502, 'account_changed', 'The requested AWS role could not be verified.');
      }
      if (expected && !sameIdentity(effectiveIdentity, expected.identity))
        fail(409, 'account_changed', 'Reconnect to approve the current AWS account and role.');
      const state = AwsConnectionMaterial.parse({ ...input, sourceIdentity, identity: effectiveIdentity });
      return { state, credentials: {
        AWS_ACCESS_KEY_ID: credentials.accessKeyId, AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
        AWS_SESSION_TOKEN: credentials.sessionToken ?? '', AWS_DEFAULT_REGION: input.region, AWS_REGION: input.region,
      } };
    } catch (error) {
      if (error instanceof DomainError) throw error;
      if (signal?.aborted) fail(409, 'cancelled', 'The operation was cancelled.');
      if (error instanceof Error && ['ExpiredToken', 'ExpiredTokenException', 'TokenRefreshRequired'].includes(error.name))
        fail(409, 'reconnect_required', 'Reconnect with current AWS credentials.');
      if (assuming) fail(502, 'role_denied', 'Check the IAM role and its trust policy for this authentication source.');
      fail(502, 'aws_authentication_failed', 'Check the AWS credentials available to the selected environment.');
    } finally { target?.destroy(); client.destroy(); }
  }
}
