import { AwsClient } from './client.mjs';
import { fail } from '../../errors.mjs';

export const configuration = env => ({ roleArn: env.FOUNDATION_AWS_ROLE_ARN || '', region: env.FOUNDATION_AWS_REGION || 'ap-northeast-1', templateBucket: env.FOUNDATION_AWS_TEMPLATE_BUCKET || '' });
export const create = env => awsRole(new AwsClient(configuration(env)));

// The first delegated grant: nothing of the account holder's is kept but the name of a role they made for
// Foundation. Each use asks AWS for an hour of credentials.
export function awsRole(client) {
  const result = assumed => ({
    subject: 'aws:' + assumed.role.account + ':' + assumed.role.name,
    privateState: { role_arn: assumed.role.arn, external_id: assumed.externalId },
    facts: { label: assumed.role.account + ' / ' + assumed.role.name, account: assumed.role.account, role: assumed.role.name, region: client.region },
    expiresAt: null,
    credentials: { environment: { AWS_ACCESS_KEY_ID: assumed.accessKeyId, AWS_SECRET_ACCESS_KEY: assumed.secretAccessKey, AWS_SESSION_TOKEN: assumed.sessionToken, AWS_DEFAULT_REGION: client.region, AWS_REGION: client.region } },
    validUntil: assumed.expiresAt,
  });
  return {
    kind: 'role', available: client.enabled,
    variables: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION'],
    authorization: {
      // The holder makes the role from the link; what Foundation must remember until they come back is the external ID.
      begin: async () => {
        const { url, externalId } = await client.prepare();
        return { url, memo: { external_id: externalId } };
      },
      complete: async ({ fields, memo }, previous) => {
        const role = client.parseRole(fields?.role_arn);
        if (previous && role.arn !== previous.privateState.role_arn) fail(409, 'account_changed', '同じAWSのIAMロールを指定してください。');
        const externalId = previous?.privateState?.external_id ?? memo?.external_id;
        const assumed = await client.assume({ roleArn: role.arn, externalId });
        return { ...result({ ...assumed, externalId }), expiresAt: null };
      },
    },
    obtain: async ({ privateState }) => {
      const assumed = await client.assume({ roleArn: privateState.role_arn, externalId: privateState.external_id });
      return { ...result({ ...assumed, externalId: privateState.external_id }), expiresAt: assumed.expiresAt };
    },
  };
}
