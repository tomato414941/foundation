import { GmailClient, GMAIL_API, GMAIL_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GOOGLE_CLIENT_ID || '', clientSecret: env.FOUNDATION_GOOGLE_CLIENT_SECRET || '' });
export const create = env => {
  const client = new GmailClient(configuration(env));
  return [gmailReadonly(client), gmailMetadata(client), gmailReadSend(client)];
};

const service = Object.freeze({ name: 'Gmail', icon: 'mail', management_url: 'https://myaccount.google.com/connections',
  api: { base_url: GMAIL_API, documentation_url: GMAIL_DOCS } });
const variables = ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GMAIL_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT'];

function gmail(client, range, description) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret, subject, range), expiresAt: secret.expires_at,
    credentials: { environment: { GOOGLE_OAUTH_ACCESS_TOKEN: secret.access_token, GMAIL_ACCOUNT_EMAIL: subject, GOOGLE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    id: 'gmail.' + range, service, label: 'Googleで接続', provider: 'gmail', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled, variables, ...description,
    ai: 'Before using Gmail, inspect scopes, missing_scopes and additional_scopes in facts from GET /v1/connections. Scope differences are reported, not blocked. Obtain current credentials with POST /v1/deliveries and {"names":[{"name":"<connection id>"}]}; Foundation refreshes tokens when needed.',
    authorization: {
      kind: 'oauth',
      begin: (context, previous) => client.authorize({ ...context, range, email: previous?.subject }),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}

export function gmailReadonly(client) {
  return gmail(client, 'readonly', {
    kind: 'メールの読み取り', intro: 'Googleアカウントでログインし、メールの読み取りを許可します。',
    access: { name: 'メールの読み取り', description: '本文・添付ファイルを含む、すべてのメール', restrictions: '送信・変更・削除は要求しません。' },
  });
}

export function gmailMetadata(client) {
  return gmail(client, 'metadata', {
    kind: '件名・差出人などの読み取り', intro: 'Googleアカウントでログインし、件名・差出人などの読み取りを許可します。',
    access: { name: '件名・差出人などの読み取り', description: '本文・添付ファイルは対象外', restrictions: '本文の取得・送信・変更・削除は要求しません。' },
  });
}

export function gmailReadSend(client) {
  return gmail(client, 'read-send', {
    kind: 'メールの読み取りと送信', intro: 'Googleアカウントでログインし、メールの読み取りと、そのアカウントからの送信を許可します。',
    access: { name: 'メールの読み取りと送信', description: '本文・添付ファイルを含むメールの読み取りと、メールの送信', restrictions: '受信メールの変更・削除や下書きの管理は要求しません。' },
  });
}
