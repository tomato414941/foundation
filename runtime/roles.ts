import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { DomainError, fail } from '../server/errors.js';

export interface RoleCredentials extends Record<string, string> {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
  AWS_DEFAULT_REGION: string;
}
export interface RoleProvider {
  obtain(arn: string, externalId: string, region: string): Promise<RoleCredentials>;
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
