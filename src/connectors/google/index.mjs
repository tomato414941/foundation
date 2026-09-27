import { GoogleClient, GOOGLE_API, GOOGLE_DOCS, GOOGLE_BASE_SCOPES, GOOGLE_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GOOGLE_CLIENT_ID || '', clientSecret: env.FOUNDATION_GOOGLE_CLIENT_SECRET || '' });
export const create = env => [googleOauth(new GoogleClient(configuration(env)))];

const service = Object.freeze({ name: 'Google', icon: 'google', management_url: 'https://myaccount.google.com/connections',
  api: { base_url: GOOGLE_API, documentation_url: GOOGLE_DOCS } });

export function googleOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { GOOGLE_OAUTH_ACCESS_TOKEN: secret.access_token, CLOUDSDK_AUTH_ACCESS_TOKEN: secret.access_token,
      GOOGLE_ACCOUNT_EMAIL: subject, GOOGLE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'google.oauth', service, label: 'Googleで接続', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'Googleアカウントでログインし、アクセスを許可します。',
    access: { name: 'Googleアカウントの操作', description: '接続のときに許可した権限の範囲で、GmailやGoogle Cloudなどを操作できます。',
      restrictions: '操作により料金が発生するサービスがあります。' },
    revocationNote: 'Google側の許可を取り消すと、同じアカウントの他のGoogle接続も使えなくなる場合があります。',
    scopes: { base: GOOGLE_BASE_SCOPES, documentationUrl: GOOGLE_SCOPE_DOCS },
    ai: 'Ask for the scopes the work needs in input.scopes (full Google scope URLs, such as https://www.googleapis.com/auth/gmail.readonly or https://www.googleapis.com/auth/cloud-platform). facts.scopes, requested_scopes, missing_scopes and additional_scopes say what was granted. GOOGLE_OAUTH_ACCESS_TOKEN is a Bearer token for Google APIs; the same token is CLOUDSDK_AUTH_ACCESS_TOKEN for gcloud. Choose a Google Cloud --project explicitly. Obtain current credentials with POST /v1/deliveries and {"names":[{"name":"<connection id>"}]}; Foundation refreshes tokens when needed.',
    variables: ['GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'GOOGLE_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT'],
    // The holder may bring their own OAuth app: the same connector, built around their client.
    oauthClient: client, withClient: googleOauth,
    authorization: {
      kind: 'oauth',
      begin: (context, previous) => client.authorize({ ...context, email: previous?.subject }),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
