import { AwsClient, AWS_API, AWS_DOCS, AWS_CONSOLE } from './client.mjs';

export const configuration = env => ({ roleArn: env.FOUNDATION_AWS_ROLE_ARN || '', region: env.FOUNDATION_AWS_REGION || 'ap-northeast-1', templateBucket: env.FOUNDATION_AWS_TEMPLATE_BUCKET || '' });
export const create = env => [awsRole(new AwsClient(configuration(env)))];

const service = Object.freeze({ name: 'AWS', icon: 'cloud', management_url: AWS_CONSOLE, api: { base_url: AWS_API, documentation_url: AWS_DOCS } });

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
    id: 'aws.role', service, label: 'AWSで役割を作る', provider: 'aws', register: 'role', credentialType: 'sts_temporary_credentials', available: client.enabled,
    intro: 'AWSの画面でFoundation用の役割を作ります。鍵は預かりません。',
    access: { name: 'AWSアカウントの操作', description: '役割に付けた権限 (管理者、または読み取りのみ) の範囲で、AWSのリソースを扱えます。', restrictions: '役割を消せば止まります。Foundationが鍵を持つことはありません。' },
    revocationNote: 'AWS側で CloudFormation のスタック foundation-connection を削除すると、この接続は使えなくなります。',
    ai: 'Delivered as AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN (valid for an hour) plus AWS_DEFAULT_REGION; the AWS CLI and SDKs read them directly. Deliver again for fresh ones. facts.account and facts.role say whose role it is.',
    variables: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION'],
    authorization: {
      kind: 'role',
      // The holder makes the role from the link; what Foundation must remember until they come back is the external ID.
      begin: async () => {
        const { url, externalId } = await client.prepare();
        return { url, fields: [{ name: 'role_arn', label: '作成された役割のARN', placeholder: 'arn:aws:iam::123456789012:role/foundation-connection-FoundationRole-...' }], memo: { external_id: externalId } };
      },
      complete: async ({ fields, memo }, previous) => {
        const externalId = previous?.privateState?.external_id ?? memo?.external_id;
        const assumed = await client.assume({ roleArn: fields?.role_arn, externalId });
        return { ...result({ ...assumed, externalId }), expiresAt: null };
      },
    },
    obtain: async ({ privateState }) => {
      const assumed = await client.assume({ roleArn: privateState.role_arn, externalId: privateState.external_id });
      return { ...result({ ...assumed, externalId: privateState.external_id }), expiresAt: assumed.expiresAt };
    },
  };
}
