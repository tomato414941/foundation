import { EbayClient, EBAY_API, EBAY_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_EBAY_CLIENT_ID || '', clientSecret: env.FOUNDATION_EBAY_CLIENT_SECRET || '', ruName: env.FOUNDATION_EBAY_RUNAME || '' });
export const create = env => [ebayOauth(new EbayClient(configuration(env)))];

const EBAY = Object.freeze({ name: 'eBay', icon: 'network', management_url: 'https://www.ebay.com/mys/home',
  api: { base_url: EBAY_API, documentation_url: EBAY_DOCS } });

export function ebayOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { EBAY_ACCESS_TOKEN: secret.access_token, EBAY_ACCOUNT_ID: subject, EBAY_USERNAME: secret.identity.username, EBAY_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'ebay.oauth', service: EBAY, label: 'eBayで接続', provider: 'ebay', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'eBayにログインし、出品と販売設定へのアクセスを許可します。',
    access: { name: '出品と販売設定の管理', description: '出品・在庫・価格と、配送・支払い・返品ポリシーを管理できます。',
      restrictions: '特定の商品には限定されません。出品の公開や変更で料金が発生する場合があります。' },
    revocationNote: 'eBay側の許可を取り消すと、この接続で取得済みの認証情報も使えなくなる場合があります。',
    ai: 'Use EBAY_ACCESS_TOKEN as a Bearer token with production eBay APIs. Requested scopes: sell.account and sell.inventory; orders, fulfillment and refunds are not requested. Before use, inspect scopes, missing_scopes and additional_scopes in facts from GET /v1/connections. Obtain current credentials with POST /v1/deliveries and {"names":[{"name":"<connection id>"}]}; Foundation refreshes tokens when needed. EBAY_OAUTH_EXPIRES_AT is Unix time in milliseconds. Expired or revoked refresh tokens require reconnection. Taxonomy APIs may require a separate application token.',
    variables: ['EBAY_ACCESS_TOKEN', 'EBAY_ACCOUNT_ID', 'EBAY_USERNAME', 'EBAY_OAUTH_EXPIRES_AT'],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous)),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
