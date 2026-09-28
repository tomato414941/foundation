import { OAuth2Client, OAUTH2_DOCS, httpsUrl } from './client.mjs';

// No configuration: Foundation holds no app of its own for services it does not know. Whoever connects brings one.
export const create = () => [oauth2(new OAuth2Client())];

// A service known only through the app registered for it: named, and pointed at, by that app.
const serviceFor = settings => ({ name: settings.service_name || 'OAuth 2.0', icon: 'key', management_url: settings.management_url || '',
  api: { base_url: settings.api_base_url || '', documentation_url: settings.documentation_url || '' } });

export function oauth2(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { OAUTH_ACCESS_TOKEN: secret.access_token, OAUTH_TOKEN_TYPE: secret.token_type,
      ...(secret.expires_at === null ? {} : { OAUTH_EXPIRES_AT: String(secret.expires_at) }) } } });
  return {
    id: 'oauth2', service: serviceFor({}), serviceFor, label: 'OAuth 2.0で接続', register: 'oauth', credentialType: 'oauth2_access_token', available: false,
    intro: 'OAuth 2.0に対応したサービスに、自分で登録したOAuthアプリを通して接続します。',
    access: { name: '許可した範囲の操作', description: '接続のときに許可した権限の範囲で、そのサービスを操作できます。', restrictions: 'Foundationはこのサービスを作り込んでいません。本人確認や取り消しは、アプリに登録したURLがある場合だけ行います。' },
    revocationNote: '取り消しのURLを登録していない場合、許可はサービス側に残ります。不要ならサービスの画面で取り消してください。',
    scopes: { base: [], documentationUrl: OAUTH2_DOCS },
    ai: 'A service Foundation has no connector for, reached through an OAuth app the owner registered (kind "app", connector "oauth2"). Ask for the scopes the work needs in input.scopes, in the service\'s own words, and name the app in input.app. OAUTH_ACCESS_TOKEN is sent as OAUTH_TOKEN_TYPE (usually Bearer) to the service\'s API; facts.label and facts.account say who authorized when the app has a userinfo URL. OAUTH_EXPIRES_AT is Unix time in milliseconds, absent when the service does not say.',
    variables: ['OAUTH_ACCESS_TOKEN', 'OAUTH_TOKEN_TYPE', 'OAUTH_EXPIRES_AT'],
    // What an app for such a service holds besides its client ID and secret: which service, and where it is.
    oauthClient: client, withClient: oauth2,
    appFields: [
      { name: 'service_name', label: 'サービス名', required: true, text: true, leading: true, placeholder: '例: Notion' },
      { name: 'authorize_url', label: '認可エンドポイントのURL', required: true, leading: true, check: httpsUrl, placeholder: 'https://example.com/oauth/authorize' },
      { name: 'token_url', label: 'トークンエンドポイントのURL', required: true, leading: true, check: httpsUrl, placeholder: 'https://example.com/oauth/token' },
      { name: 'userinfo_url', label: '利用者情報のURL', check: httpsUrl, note: '登録すると、接続したアカウントを確かめ、一覧に名前を出します。' },
      { name: 'revoke_url', label: '取り消しのURL', check: httpsUrl, note: '登録すると、接続の解除のときにサービス側の許可も取り消せます。' },
      { name: 'api_base_url', label: 'APIのURL', check: httpsUrl },
    ],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    // Only an app with a revocation URL can take a grant back at the service.
    ...(client.revokeUrl ? { revoke: privateState => client.revoke(privateState) } : {}),
  };
}
