import { EbayClient, EBAY_API, EBAY_DOCS, EBAY_BASE_SCOPES, EBAY_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_EBAY_CLIENT_ID || '', clientSecret: env.FOUNDATION_EBAY_CLIENT_SECRET || '', ruName: env.FOUNDATION_EBAY_RUNAME || '' });
export const create = env => [ebayOauth(new EbayClient(configuration(env)))];

const EBAY = Object.freeze({ name: 'eBay', icon: 'network', management_url: 'https://www.ebay.com/mys/home',
  api: { base_url: EBAY_API, documentation_url: EBAY_DOCS } });

export function ebayOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { EBAY_ACCESS_TOKEN: secret.access_token, EBAY_ACCOUNT_ID: subject, EBAY_USERNAME: secret.identity.username, EBAY_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'ebay.oauth', service: EBAY, label: 'eBayで接続', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'eBayにログインし、アクセスを許可します。',
    access: { name: 'eBayアカウントの操作', description: '接続のときに許可した権限の範囲で、eBayの出品や販売設定などを操作できます。',
      restrictions: '出品の公開や変更で料金が発生する場合があります。' },
    scopes: { base: EBAY_BASE_SCOPES, documentationUrl: EBAY_SCOPE_DOCS },
    revocationNote: 'eBay側の許可を取り消すと、この接続で取得済みの認証情報も使えなくなる場合があります。',
    ai: 'Use EBAY_ACCESS_TOKEN as a Bearer token with production eBay APIs. Ask for the scopes the work needs in input.scopes (full eBay scope URLs, such as https://api.ebay.com/oauth/api_scope/sell.inventory); only scopes enabled for the application can be granted. facts.scopes, requested_scopes, missing_scopes and additional_scopes say what was granted. Obtain current credentials with POST /v1/deliveries and {"names":[{"name":"<connection id>"}]}; Foundation refreshes tokens when needed. EBAY_OAUTH_EXPIRES_AT is Unix time in milliseconds. Expired or revoked refresh tokens require reconnection. Taxonomy APIs may require a separate application token.',
    variables: ['EBAY_ACCESS_TOKEN', 'EBAY_ACCOUNT_ID', 'EBAY_USERNAME', 'EBAY_OAUTH_EXPIRES_AT'],
    // The holder may bring their own OAuth app: the same connector, built around their client.
    oauthClient: client, withClient: ebayOauth, appFields: [{ name: 'ru_name', label: 'RuName', required: true }],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous)),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
