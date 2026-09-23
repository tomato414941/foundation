import { fail } from './errors.mjs';
import { GMAIL_API, GMAIL_DOCS } from './services/gmail.mjs';
import { OPENROUTER_API, OPENROUTER_DOCS } from './services/openrouter.mjs';
import { GITHUB_API, GITHUB_DOCS, GITHUB_SETTINGS } from './services/github.mjs';

// An adapter performs a built-in OAuth flow and describes its credential outputs.
// Renewal state belongs to that connection. Output identifiers do not reserve saved names.
//
// Everything a person can simply go and fetch for themselves has no adapter. There the owner is asked
// to put the value into storage, following instructions the requesting AI wrote, and Foundation holds
// no knowledge of that service at all.
//
//   register  'oauth'
//   client    how it is obtained, checked with the service and kept fresh
//   variables the environment variables it is delivered as; deliver() may set no others
//   deliver   what the command receives, built from what the client returned
const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const GMAIL = service('Gmail', 'mail', 'https://myaccount.google.com/connections', { base_url: GMAIL_API, documentation_url: GMAIL_DOCS });
const OPENROUTER = service('OpenRouter', 'network', 'https://openrouter.ai/keys', { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS });
const GITHUB = service('GitHub', 'code', GITHUB_SETTINGS, { base_url: GITHUB_API, documentation_url: GITHUB_DOCS });

const GMAIL_VARIABLES = ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GMAIL_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT'];
const gmailDelivery = (secret, credential) => ({ environment: { GOOGLE_OAUTH_ACCESS_TOKEN: secret.access_token, GMAIL_ACCOUNT_EMAIL: credential.subject, GOOGLE_OAUTH_EXPIRES_AT: String(secret.expires_at) } });

export function gmailReadonly(client) {
  return {
    id: 'gmail.readonly', service: GMAIL, kind: 'メールの読み取り', label: 'Googleで接続', register: 'oauth', client, range: 'readonly',
    intro: 'Googleアカウントでログインし、メールの読み取りを許可します。',
    access: { name: 'メールの読み取り', description: '本文・添付ファイルを含む、すべてのメール', restrictions: '送信・変更・削除は許可しません。' },
    variables: GMAIL_VARIABLES, deliver: gmailDelivery,
  };
}

export function gmailMetadata(client) {
  return {
    id: 'gmail.metadata', service: GMAIL, kind: '件名・差出人などの読み取り', label: 'Googleで接続', register: 'oauth', client, range: 'metadata',
    intro: 'Googleアカウントでログインし、件名・差出人などの読み取りを許可します。',
    access: { name: '件名・差出人などの読み取り', description: '本文・添付ファイルは対象外', restrictions: '本文の取得・送信・変更・削除は許可しません。' },
    variables: GMAIL_VARIABLES, deliver: gmailDelivery,
  };
}

export function openrouterOauth(client) {
  return {
    id: 'openrouter.oauth', service: OPENROUTER, label: 'OpenRouterで接続', register: 'oauth', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    // OpenRouter makes the key before Foundation receives it, so a registration that fails can leave one behind.
    failureNote: { text: '登録できなくても、OpenRouterで作成済みのキーが残る場合があります。', link: '不要なキーはOpenRouterで削除してください', href: 'https://openrouter.ai/keys' },
    intro: 'OpenRouterでログインし、Foundation用のキーを作成します。',
    access: { name: 'APIキーの利用', description: 'このキーの権限でOpenRouter APIを利用できます。モデルの実行は課金を伴う場合があります。', restrictions: '利用上限と有効期限はOpenRouter側の設定が適用されます。読み取り専用のキーではありません。' },
    variables: ['OPENROUTER_API_KEY'], deliver: secret => ({ environment: { OPENROUTER_API_KEY: secret.access_token } }),
  };
}

// gh reads GH_TOKEN; many other tools read GITHUB_TOKEN. git reaches GitHub through gh (gh auth setup-git).
export function githubOauth(client) {
  return {
    id: 'github.oauth', service: GITHUB, label: 'GitHubで接続', register: 'oauth', client,
    intro: 'GitHubでログインし、リポジトリへのアクセスを許可します。',
    access: { name: 'リポジトリの読み書き', description: 'あなたがアクセスできるすべてのリポジトリ (非公開を含む) の読み書き、Actions のワークフローの変更、Gist の作成、組織の閲覧', restrictions: 'リポジトリや組織の削除・管理者設定の変更は許可しません。登録を解除すると、GitHub側の許可も取り消します。' },
    ai: 'gh and most tools read it directly. For git push/pull, run gh auth setup-git inside the exec, then use git. Scopes: repo, workflow, read:org, gist.',
    variables: ['GH_TOKEN', 'GITHUB_TOKEN'], deliver: secret => ({ environment: { GH_TOKEN: secret.access_token, GITHUB_TOKEN: secret.access_token } }),
  };
}


export class Adapters {
  constructor(adapters) {
    this.adapters = new Map(adapters.map(adapter => [adapter.id, adapter]));
  }
  get(id) {
    const adapter = typeof id === 'string' && this.adapters.get(id);
    if (!adapter) fail(400, 'invalid_adapter', '対応している接続方法を指定してください。');
    return adapter;
  }
  ids() { return [...this.adapters.keys()]; }
  service(id) { return this.get(id).service; }
  variables(id) { return this.get(id).variables; }
  delivered(id) { return this.get(id).variables; }
  describe(id) {
    const adapter = this.get(id);
    return { id, service: adapter.service, label: adapter.label, register: adapter.register, available: adapter.client.enabled,
      intro: adapter.intro || '', access: adapter.access, variables: adapter.variables,
      ...(adapter.ai ? { ai: adapter.ai } : {}), ...(adapter.kind ? { kind: adapter.kind } : {}), ...(adapter.failureNote ? { failure_note: adapter.failureNote } : {}),
      can_reconnect: adapter.canReconnect !== false, can_revoke: adapter.canRevoke !== false, credential_type: adapter.credentialType || 'oauth2_access_token' };
  }
}
