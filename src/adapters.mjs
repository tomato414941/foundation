import { fail } from './errors.mjs';
import { defineSchema } from './schema.mjs';
import { GMAIL_API, GMAIL_DOCS } from './services/gmail.mjs';
import { OPENROUTER_API, OPENROUTER_DOCS } from './services/openrouter.mjs';
import { EXPO_API, EXPO_DOCS, EXPO_TOKENS } from './services/expo.mjs';
import { SUPABASE_API, SUPABASE_DOCS, SUPABASE_TOKENS } from './services/supabase.mjs';
import { APPLE_API, APPLE_DOCS, APPLE_KEYS } from './services/apple.mjs';
import { CLOUDFLARE_API, CLOUDFLARE_DOCS, CLOUDFLARE_TOKENS } from './services/cloudflare.mjs';
import { GITHUB_API, GITHUB_DOCS, GITHUB_SETTINGS } from './services/github.mjs';

// The unit Foundation holds is a credential: one thing the owner handed over.
// An adapter is how a credential of one kind is handled over its whole life:
//   register  how the owner hands it over: 'paste' (values checked against a schema), 'oauth', or 'login'
//   schema    for 'paste': what the owner hands over
//   client    how it is checked with the service and kept fresh
//   variables the environment variables it is delivered as; deliver() may set no others
//   deliver   what the command receives, built from the stored secret at the moment of use
// The service is what the credential reaches: a name, an icon, where the owner manages it.
// It is an attribute of the adapter, or for the generic adapter what the runtime declared.
const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const GMAIL = service('Gmail', 'mail', 'https://myaccount.google.com/connections', { base_url: GMAIL_API, documentation_url: GMAIL_DOCS });
const OPENROUTER = service('OpenRouter', 'network', 'https://openrouter.ai/keys', { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS });
const EXPO = service('Expo', 'device', EXPO_TOKENS, { base_url: EXPO_API, documentation_url: EXPO_DOCS });
const SUPABASE = service('Supabase', 'database', SUPABASE_TOKENS, { base_url: SUPABASE_API, documentation_url: SUPABASE_DOCS });
const CLOUDFLARE = service('Cloudflare', 'cloud', CLOUDFLARE_TOKENS, { base_url: CLOUDFLARE_API, documentation_url: CLOUDFLARE_DOCS });
const GITHUB = service('GitHub', 'code', GITHUB_SETTINGS, { base_url: GITHUB_API, documentation_url: GITHUB_DOCS });
const APPLE = service('Apple', 'key', APPLE_KEYS, { base_url: APPLE_API, documentation_url: APPLE_DOCS });

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
    ai: 'gh と多くのツールがそのまま使える。git の push/pull は gh 経由の認証で行う (exec の中で gh auth setup-git してから git を使う)。スコープは repo, workflow, read:org, gist。',
    variables: ['GH_TOKEN', 'GITHUB_TOKEN'], deliver: secret => ({ environment: { GH_TOKEN: secret.access_token, GITHUB_TOKEN: secret.access_token } }),
  };
}

export function expoToken(client) {
  return {
    id: 'expo.token', service: EXPO, kind: 'アクセストークン', label: 'Expoのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'Expoで発行したアクセストークンを登録します。',
    links: [{ label: 'Expoのアクセストークン管理ページを開く', href: EXPO_TOKENS }],
    schema: defineSchema([{ id: 'token', label: 'アクセストークン', secret: true }]),
    instructions: 'Expoのアクセストークン (個人用またはRobot) を受け付けます。登録時にExpoへ照会して持ち主を確認します。',
    access: { name: 'トークンの権限でExpoを利用', description: '個人用トークンは、本人がアクセスできるすべてのアカウント・組織で操作できます。ビルドなどは課金を伴う場合があります。', restrictions: '読み取り専用ではありません。対象や操作を絞る場合は、Expoで権限を制限したRobotのトークンを使ってください。' },
    ai: 'アクセストークン (個人用または Robot) を受け付ける。',
    variables: ['EXPO_TOKEN'], deliver: secret => ({ environment: { EXPO_TOKEN: secret.access_token } }),
  };
}

// Foundation relays the owner's Expo password to Expo once; only the resulting session is kept,
// and the command receives it as Expo's own login state rather than as a variable.
export function expoLogin(client) {
  return {
    id: 'expo.login', service: EXPO, kind: 'ログイン', label: 'Expoにログイン', register: 'login', client, canReconnect: false, credentialType: 'expo_session',
    intro: 'Expoにログインして登録します。',
    access: { name: 'Expoアカウントの利用', description: 'このAIに、Expoであなたと同じ権限での操作を許可します。ビルド・公開など、課金を伴う操作も含みます。', restrictions: '登録を解除すると、このログインセッションを無効にできます。' },
    ai: 'Expo のログインセッションを、exec の間だけ Expo 自身のログイン状態として渡す (eas などがそのまま読む)。環境変数は使わない。',
    variables: [], deliver: secret => ({ expo_session: { secret: secret.access_token, profile: { user_id: secret.details.actor_id, username: secret.details.label } } }),
  };
}

export function supabaseAccessToken(client) {
  return {
    id: 'supabase.access-token', service: SUPABASE, label: 'Supabaseのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'Supabaseで発行したアクセストークンを登録します。',
    links: [{ label: 'Supabaseのアクセストークン管理ページを開く', href: SUPABASE_TOKENS }],
    schema: defineSchema([{ id: 'token', label: 'アクセストークン', secret: true }]),
    instructions: 'Supabaseのアカウントのアクセストークン (sbp_ で始まる) を受け付けます。登録時にSupabaseへ照会して持ち主を確認します。',
    access: { name: 'アカウントの権限でSupabaseを利用', description: 'アカウントがアクセスできるすべての組織とプロジェクトを、Management APIとCLIから操作できます。プロジェクトの作成・削除や設定変更も含みます。', restrictions: '読み取り専用ではありません。プロジェクトのデータベースのキー (anon / service_role) はこのトークンでは渡しません。' },
    ai: 'アカウントのアクセストークン (sbp_...) を受け付ける。Supabase CLI は SUPABASE_ACCESS_TOKEN を読む。',
    variables: ['SUPABASE_ACCESS_TOKEN'], deliver: secret => ({ environment: { SUPABASE_ACCESS_TOKEN: secret.access_token } }),
  };
}

export function cloudflareApiToken(client) {
  return {
    id: 'cloudflare.api-token', service: CLOUDFLARE, label: 'Cloudflareのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'APIトークンでR2に接続します。',
    links: [{ label: 'CloudflareのAPIトークン管理ページを開く', href: CLOUDFLARE_TOKENS }],
    schema: defineSchema([
      { id: 'account_id', label: 'アカウントID', pattern: '[a-fA-F0-9]{32}', max: 32 },
      { id: 'token', label: 'APIトークン', secret: true },
    ]),
    instructions: 'CloudflareのユーザーAPIトークンを受け付けます (Global API Key と R2 の S3互換キーは不可)。登録時に有効性と、指定アカウントの R2 一覧の取得可否を確認します。',
    note: '登録時にR2の一覧へのアクセスを確認します。トークンの権限全体は確認・制限しません。',
    access: { name: 'トークンの権限でCloudflareを利用', description: 'APIトークンを登録し、指定したアカウントでR2の一覧を取得できるか確認します。', restrictions: '利用できる範囲はトークンに与えた全権限です。ここで指定するアカウントIDや用途では制限されません。読み取り専用のトークンを使ってください。' },
    ai: 'ユーザー API トークンとアカウント ID を受け付ける (Global API Key と R2 の S3 互換キーは不可)。バケット一覧は公式 API の /accounts/<cloudflare_account_id>/r2/buckets (ページ送りは result_info.cursor)。Foundation はトークン全体の権限を狭めない。',
    variables: ['CLOUDFLARE_API_TOKEN'], deliver: secret => ({ environment: { CLOUDFLARE_API_TOKEN: secret.access_token } }),
  };
}

// App Store Connect API key for EAS: the .p8 travels as a file that exists only
// while the command runs; the identifiers travel as plain environment variables.
export function appleApiKey(client) {
  return {
    id: 'apple.api-key', service: APPLE, label: 'AppleのAPIキーを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'private_key',
    intro: 'App Store ConnectのAPIキー (.p8) と識別情報を登録します。',
    links: [{ label: 'App Store Connect の「統合」を開く', href: APPLE_KEYS }],
    schema: defineSchema([
      { id: 'key_id', label: 'Key ID', pattern: '[A-Za-z0-9]{10}', max: 10 },
      { id: 'issuer_id', label: 'Issuer ID', pattern: '[0-9a-fA-F-]{36}', max: 36 },
      { id: 'team_id', label: 'Team ID', pattern: '[A-Za-z0-9]{10}', max: 10 },
      { id: 'team_type', label: 'チーム種別', kind: 'choice', options: [{ value: 'INDIVIDUAL', label: '個人 (Individual)' }, { value: 'COMPANY_OR_ORGANIZATION', label: '法人・組織 (Company / Organization)' }, { value: 'IN_HOUSE', label: '社内配布 (In-House)' }] },
      { id: 'key', label: 'APIキー (.p8 の内容)', kind: 'multiline', secret: true },
    ]),
    instructions: 'App Store Connect API のチームキー (.p8) と、Key ID・Issuer ID・Team ID・チーム種別を受け付けます。登録時にAppleへ1回読み取りで照会して確認します。',
    note: '登録時にAppleへ1回だけ読み取りで問い合わせ、キーが有効か確認します。証明書やプロファイルの作成はEASが行い、Foundationは関与しません。',
    access: { name: 'App Store Connect APIキーの権限でAppleを利用', description: 'このキーにAppleで与えた役割の範囲で、アプリID・端末・証明書・プロビジョニングプロファイルの作成や更新ができます。', restrictions: '読み取り専用ではありません。Team API キーは単一アプリに限定できません。' },
    ai: 'チームキーの .p8 と Key ID / Issuer ID / Team ID / チーム種別を受け付ける。.p8 は exec の間だけ存在するファイルで渡す。EAS の署名準備には Admin の役割が要る。',
    variables: ['EXPO_ASC_API_KEY_PATH', 'EXPO_ASC_KEY_ID', 'EXPO_ASC_ISSUER_ID', 'EXPO_APPLE_TEAM_ID', 'EXPO_APPLE_TEAM_TYPE'],
    deliver: secret => ({ files: [{ env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey_' + secret.details.key_id + '.p8', content: secret.access_token }],
      environment: { EXPO_ASC_KEY_ID: secret.details.key_id, EXPO_ASC_ISSUER_ID: secret.details.issuer_id, EXPO_APPLE_TEAM_ID: secret.details.team_id, EXPO_APPLE_TEAM_TYPE: secret.details.team_type } }),
  };
}

// The adapter with no service of its own: the runtime declares the service, where the key is made,
// and the fields, each delivered under its own name. Foundation neither checks nor converts.
export function generic(client) {
  return {
    id: 'generic', service: null, label: 'キーを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key', declared: true,
    intro: 'サービスの設定画面で作成したキーを登録します。Foundationはキーの権限や有効性を検証しません。',
    access: { name: 'キーの権限で利用', description: 'このキーで行える操作は、サービス側でキーに与えた権限のとおりです。Foundationはその内容を確認できません。', restrictions: '読み取り専用とは限りません。範囲を絞る場合は、サービス側で権限を制限したキーを作成してください。' },
    ai: 'foundation connect --service <サービス名> --site <https://キー作成ページ> --field <環境変数名>[=<表示名>] [--field ...] [--multiline-field ...] で申告する。--field ごとに 1 つ値を受け取り、その名前の環境変数で渡す。値は検証しない。',
    deliver: secret => ({ environment: { ...secret.values } }),
  };
}

export class Adapters {
  constructor(adapters) {
    this.adapters = new Map(adapters.map(adapter => [adapter.id, adapter]));
    // Variables that built-in adapters deliver; a runtime may not declare them for the generic adapter.
    this.owned = new Set(adapters.flatMap(adapter => adapter.variables || []));
  }
  get(id) {
    const adapter = typeof id === 'string' && this.adapters.get(id);
    if (!adapter) fail(400, 'invalid_adapter', '対応している接続方法を指定してください。');
    return adapter;
  }
  ids() { return [...this.adapters.keys()]; }
  // What a runtime declared on a request, checked by the adapter that reads it. Only a declaring adapter takes any.
  details(id, input) { const adapter = this.get(id); return adapter.declared ? adapter.client.details(input, this.owned) : {}; }
  // What the credential reaches. For the generic adapter, what the runtime declared.
  service(id, details) {
    const adapter = this.get(id);
    if (!adapter.declared) return adapter.service;
    return details?.service ? service(details.service, 'key', details.site, { base_url: '', documentation_url: '' }) : null;
  }
  variables(id, details) { const adapter = this.get(id); return adapter.declared ? (details ? adapter.client.variables(details) : []) : adapter.variables; }
  // What the registration form shows and accepts.
  form(id, details) {
    const adapter = this.get(id);
    if (adapter.register !== 'paste') return null;
    if (adapter.declared) return details ? { schema: adapter.client.schema(details), links: [{ label: details.site, href: details.site, declared: true }] } : null;
    return { schema: adapter.schema, links: adapter.links || [] };
  }
  // The variables a stored credential is delivered as. For the generic adapter, the fields it was registered with.
  delivered(id, secret) { const adapter = this.get(id); return adapter.declared ? secret.details.fields : adapter.variables; }
  // What a command receives. An adapter may set only the variables it declares.
  deliver(id, secret, credential) {
    const { environment = {}, files = [], expo_session } = this.get(id).deliver(secret, credential);
    const allowed = new Set(this.delivered(id, secret));
    for (const name of [...Object.keys(environment), ...files.map(file => file.env)]) if (!allowed.has(name)) throw new Error('Adapter ' + id + ' delivered an undeclared variable: ' + name);
    return { environment, files, ...(expo_session ? { expo_session } : {}) };
  }
  describe(id, details) {
    const adapter = this.get(id), form = this.form(id, details);
    return { id, service: this.service(id, details), label: adapter.declared && details?.service ? details.service + 'のキーを登録' : adapter.label, register: adapter.register, available: adapter.client.enabled,
      intro: adapter.intro || '', access: adapter.access, variables: this.variables(id, details), declared: Boolean(adapter.declared), request_fields: adapter.declared ? [{ id: 'service', label: 'サービス' }, { id: 'site', label: 'キーの作成ページ', type: 'url' }] : [],
      ...(adapter.instructions ? { instructions: adapter.instructions } : {}), ...(adapter.ai ? { ai: adapter.ai } : {}), ...(adapter.note ? { note: adapter.note } : {}), ...(adapter.kind ? { kind: adapter.kind } : {}), ...(adapter.failureNote ? { failure_note: adapter.failureNote } : {}), ...(form ? { form } : {}),
      can_reconnect: adapter.canReconnect !== false, can_revoke: adapter.canRevoke !== false, credential_type: adapter.credentialType || 'oauth2_access_token' };
  }
}
