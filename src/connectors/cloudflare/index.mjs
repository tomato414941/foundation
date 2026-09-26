import { CloudflareClient, CLOUDFLARE_API, CLOUDFLARE_DOCS, CLOUDFLARE_SETTINGS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_CLOUDFLARE_CLIENT_ID || '', clientSecret: env.FOUNDATION_CLOUDFLARE_CLIENT_SECRET || '' });
export const create = env => [cloudflareOauth(new CloudflareClient(configuration(env)))];

const service = Object.freeze({ name: 'Cloudflare', icon: 'cloud', management_url: CLOUDFLARE_SETTINGS,
  api: { base_url: CLOUDFLARE_API, documentation_url: CLOUDFLARE_DOCS } });

export function cloudflareOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { CLOUDFLARE_API_TOKEN: secret.access_token, CLOUDFLARE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'cloudflare.oauth', service, label: 'Cloudflareで接続', provider: 'cloudflare', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'Cloudflareで対象のアカウントを選び、アクセスを許可します。',
    access: { name: 'ドメインとDNSの管理', description: 'アカウント情報の読み取り、DNSレコードの編集、ドメインの登録・更新などの管理を行えます。',
      restrictions: '選択したアカウントのドメインが対象です。ドメインの登録・更新には料金がかかります。' },
    ai: 'Use CLOUDFLARE_API_TOKEN as a Bearer token with Cloudflare v4 APIs. Inspect facts.scopes, missing_scopes and additional_scopes; differences are reported, not blocked. List /accounts and choose the target explicitly: facts.user_id identifies the user, not a Cloudflare account. Domain registrations and renewals incur charges. Invoke connection.credentials again before expiry; saved copies do not refresh. CLOUDFLARE_OAUTH_EXPIRES_AT is Unix time in milliseconds. Revoked consent is detected on the next token refresh.',
    variables: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_OAUTH_EXPIRES_AT'],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous)),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
