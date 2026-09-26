import { GcpClient, GCP_API, GCP_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GCP_CLIENT_ID || '', clientSecret: env.FOUNDATION_GCP_CLIENT_SECRET || '' });
export const create = env => [gcpOauth(new GcpClient(configuration(env)))];

const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const GCP = service('Google Cloud', 'cloud', 'https://myaccount.google.com/connections', { base_url: GCP_API, documentation_url: GCP_DOCS });

export function gcpOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { CLOUDSDK_AUTH_ACCESS_TOKEN: secret.access_token, GOOGLE_CLOUD_ACCOUNT_EMAIL: secret.identity.email, GOOGLE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'gcp.oauth', service: GCP, label: 'Googleで接続', provider: 'gcp', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'Googleアカウントでログインし、Google Cloudへのアクセスを許可します。',
    access: { name: 'Google Cloudの操作', description: '許可した範囲とアカウントのIAM権限に従い、リソースの作成・変更・削除を行えます。', restrictions: '特定のプロジェクトには限定されません。操作により料金が発生する場合があります。' },
    revocationNote: 'Google側の許可を取り消すと、同じアカウントの他のGoogle接続も使えなくなる場合があります。',
    ai: 'Use CLOUDSDK_AUTH_ACCESS_TOKEN with gcloud or as a Bearer token with the relevant Google Cloud API. Inspect facts.scopes, missing_scopes and additional_scopes in the connection list or credential function result; differences are reported, not blocked. IAM is not checked. Choose --project explicitly: it is not an access restriction. Invoke connection.credentials again before token expiry; saved copies do not refresh.',
    variables: ['CLOUDSDK_AUTH_ACCESS_TOKEN', 'GOOGLE_CLOUD_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT'],
    authorization: {
      kind: 'oauth',
      begin: (context, previous) => client.authorize({ ...context, email: previous?.subject }),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
