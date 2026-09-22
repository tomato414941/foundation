import { fail } from './errors.mjs';
import { defineSchema } from './schema.mjs';
import { GMAIL_API, GMAIL_DOCS, METADATA_SCOPE, READONLY_SCOPE } from './services/gmail.mjs';
import { OPENROUTER_API, OPENROUTER_DOCS } from './services/openrouter.mjs';
import { EXPO_API, EXPO_DOCS, EXPO_TOKENS } from './services/expo.mjs';
import { SUPABASE_API, SUPABASE_DOCS, SUPABASE_TOKENS } from './services/supabase.mjs';
import { APPLE_API, APPLE_DOCS, APPLE_KEYS } from './services/apple.mjs';
import { AWS_DOCS, AWS_KEYS, AWS_TEMPLATE_PATH, quickCreateUrl } from './services/aws.mjs';
import { CLOUDFLARE_API, CLOUDFLARE_DOCS, CLOUDFLARE_TOKENS } from './services/cloudflare.mjs';

// A service is what the owner recognises: a name, an icon, where its keys are managed.
// It says nothing about how Foundation connects to it.
export const SERVICES = Object.freeze({
  gmail: { name: 'Gmail', icon: 'mail', management_url: 'https://myaccount.google.com/connections', api: { base_url: GMAIL_API, documentation_url: GMAIL_DOCS } },
  openrouter: { name: 'OpenRouter', icon: 'network', management_url: 'https://openrouter.ai/keys', api: { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS } },
  expo: { name: 'Expo', icon: 'device', management_url: EXPO_TOKENS, api: { base_url: EXPO_API, documentation_url: EXPO_DOCS } },
  supabase: { name: 'Supabase', icon: 'database', management_url: SUPABASE_TOKENS, api: { base_url: SUPABASE_API, documentation_url: SUPABASE_DOCS } },
  cloudflare: { name: 'Cloudflare', icon: 'cloud', management_url: CLOUDFLARE_TOKENS, api: { base_url: CLOUDFLARE_API, documentation_url: CLOUDFLARE_DOCS } },
  apple: { name: 'Apple', icon: 'key', management_url: APPLE_KEYS, api: { base_url: APPLE_API, documentation_url: APPLE_DOCS } },
  aws: { name: 'AWS', icon: 'cloud', management_url: AWS_KEYS, api: { base_url: '', documentation_url: AWS_DOCS } },
});

// An adapter is one way of connecting to one service. It fits Foundation's common contract
// (receive what the schema says, verify, hand over as environment variables) to that way.
//   register  how the owner hands the credential over: 'paste' | 'oauth' | 'login'
//   schema    for 'paste': what the owner hands over
//   deliver   how the runtime receives it: { env, file, environment } from the stored credential
//   matches   when an adapter has several permissions, whether a credential satisfies one
export function gmailOauth(client) {
  return {
    id: 'gmail.oauth', service: 'gmail', label: 'Googleで接続', register: 'oauth', client,
    intro: 'Googleアカウントと読み取り範囲を選べます。',
    permissions: [
      { id: 'readonly', name: 'メールの読み取り', description: '本文・添付ファイルを含む、すべてのメール', restrictions: '送信・変更・削除は許可しません。' },
      { id: 'metadata', name: '件名・差出人などの読み取り', description: '本文・添付ファイルは対象外', restrictions: '本文の取得・送信・変更・削除は許可しません。' },
    ],
    matches: (permission, account) => permission === 'readonly' ? account.scopes.includes(READONLY_SCOPE) : account.scopes.includes(METADATA_SCOPE) && !account.scopes.includes(READONLY_SCOPE),
    deliver: (credentials, account) => ({ env: 'GOOGLE_OAUTH_ACCESS_TOKEN', environment: { GMAIL_ACCOUNT_EMAIL: account.subject, GOOGLE_OAUTH_EXPIRES_AT: String(credentials.expires_at) } }),
  };
}

export function openrouterOauth(client) {
  return {
    id: 'openrouter.oauth', service: 'openrouter', label: 'OpenRouterで接続', register: 'oauth', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'OpenRouterでログインし、接続用のキーを作成します。',
    permissions: [{ id: 'api-key', name: 'APIキーの利用', description: 'このキーの権限でOpenRouter APIを利用できます。モデルの実行は課金を伴う場合があります。', restrictions: '利用上限と有効期限はOpenRouter側の設定が適用されます。読み取り専用のキーではありません。' }],
    deliver: () => ({ env: 'OPENROUTER_API_KEY' }),
  };
}

export function expoToken(client) {
  return {
    id: 'expo.token', service: 'expo', label: 'Expoのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'Expoで発行したアクセストークンを登録します。',
    links: [{ label: 'Expoのアクセストークン管理ページを開く', href: EXPO_TOKENS }],
    schema: defineSchema([{ id: 'token', label: 'アクセストークン', secret: true }]),
    instructions: 'Expoのアクセストークン (個人用またはRobot) を受け付けます。登録時にExpoへ照会して持ち主を確認します。',
    permissions: [{ id: 'access-token', name: 'トークンの権限でExpoを利用', description: '個人用トークンは、本人がアクセスできるすべてのアカウント・組織で操作できます。ビルドなどは課金を伴う場合があります。', restrictions: '読み取り専用ではありません。対象や操作を絞る場合は、Expoで権限を制限したRobotのトークンを使ってください。' }],
    deliver: () => ({ env: 'EXPO_TOKEN' }),
  };
}

// Foundation relays the owner's Expo password to Expo once; only the resulting session is kept.
export function expoLogin(client) {
  return {
    id: 'expo.login', service: 'expo', label: 'Expoにログイン', register: 'login', client, canReconnect: false, credentialType: 'expo_session',
    intro: 'Expoにログインして接続します。',
    permissions: [{ id: 'session', name: 'Expoアカウントの利用', description: 'このAIに、Expoであなたと同じ権限での操作を許可します。ビルド・公開など、課金を伴う操作も含みます。', restrictions: '接続を解除すると、この接続のログインセッションを無効にできます。' }],
    deliver: () => ({}),
  };
}

export function supabaseAccessToken(client) {
  return {
    id: 'supabase.access-token', service: 'supabase', label: 'Supabaseのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'Supabaseで発行したアクセストークンを登録します。',
    links: [{ label: 'Supabaseのアクセストークン管理ページを開く', href: SUPABASE_TOKENS }],
    schema: defineSchema([{ id: 'token', label: 'アクセストークン', secret: true }]),
    instructions: 'Supabaseのアカウントのアクセストークン (sbp_ で始まる) を受け付けます。登録時にSupabaseへ照会して持ち主を確認します。',
    permissions: [{ id: 'access-token', name: 'アカウントの権限でSupabaseを利用', description: 'アカウントがアクセスできるすべての組織とプロジェクトを、Management APIとCLIから操作できます。プロジェクトの作成・削除や設定変更も含みます。', restrictions: '読み取り専用ではありません。プロジェクトのデータベースのキー (anon / service_role) はこのトークンでは渡しません。' }],
    deliver: () => ({ env: 'SUPABASE_ACCESS_TOKEN' }),
  };
}

export function cloudflareApiToken(client) {
  return {
    id: 'cloudflare.api-token', service: 'cloudflare', label: 'Cloudflareのトークンを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'APIトークンでR2に接続します。',
    links: [{ label: 'CloudflareのAPIトークン管理ページを開く', href: CLOUDFLARE_TOKENS }],
    schema: defineSchema([
      { id: 'account_id', label: 'アカウントID', pattern: '[a-fA-F0-9]{32}', max: 32 },
      { id: 'token', label: 'APIトークン', secret: true },
    ]),
    instructions: 'CloudflareのユーザーAPIトークンを受け付けます (Global API Key と R2 の S3互換キーは不可)。登録時に有効性と、指定アカウントの R2 一覧の取得可否を確認します。',
    note: '登録時にR2の一覧へのアクセスを確認します。トークンの権限全体は確認・制限しません。',
    permissions: [{ id: 'api-token', name: 'トークンの権限でCloudflareを利用', description: 'APIトークンを登録し、指定したアカウントでR2の一覧を取得できるか確認します。', restrictions: '利用できる範囲はトークンに与えた全権限です。ここで指定するアカウントIDや用途では制限されません。読み取り専用のトークンを使ってください。' }],
    deliver: () => ({ env: 'CLOUDFLARE_API_TOKEN' }),
  };
}

// App Store Connect API key for EAS: the .p8 travels as a file that exists only
// while the command runs; the identifiers travel as plain environment variables.
export function appleApiKey(client) {
  return {
    id: 'apple.api-key', service: 'apple', label: 'AppleのAPIキーを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'private_key',
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
    permissions: [{ id: 'api-key', name: 'App Store Connect APIキーの権限でAppleを利用', description: 'このキーにAppleで与えた役割の範囲で、アプリID・端末・証明書・プロビジョニングプロファイルの作成や更新ができます。', restrictions: '読み取り専用ではありません。Team API キーは単一アプリに限定できません。' }],
    deliver: credentials => ({ file: { env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey_' + credentials.details.key_id + '.p8' },
      environment: { EXPO_ASC_KEY_ID: credentials.details.key_id, EXPO_ASC_ISSUER_ID: credentials.details.issuer_id, EXPO_APPLE_TEAM_ID: credentials.details.team_id, EXPO_APPLE_TEAM_TYPE: credentials.details.team_type } }),
  };
}

// Foundation keeps an IAM user key and issues temporary credentials for one role on every exec.
// Duration is the runtime's request and AWS's decision.
export function awsIamUserKey(client, { templateUrl = '', region = 'ap-northeast-1' } = {}) {
  const quickCreate = quickCreateUrl(templateUrl, region);
  return {
    id: 'aws.iam-user-key', service: 'aws', label: 'AWSのアクセスキーを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key',
    intro: 'IAMユーザーのアクセスキーと、AIに使わせるロールを登録します。AIには一時的な認証情報だけを渡します。',
    links: quickCreate ? [{ label: 'AWS で作成する', href: quickCreate }] : [{ label: '定義ファイルをダウンロード', href: AWS_TEMPLATE_PATH }, { label: 'CloudFormation を開く', href: `https://${region}.console.aws.amazon.com/cloudformation/home?region=${region}#/stacks/create` }],
    schema: defineSchema([{ id: 'code', label: 'AWSの「出力」に表示された値 (CopyToFoundation)', secret: true }]),
    instructions: 'CloudFormationのスタックが作った「出力」の CopyToFoundation の値 1 つを受け付けます。登録時に GetCallerIdentity と AssumeRole を1回ずつ試して確認します。',
    note: '作られるのは、ロールを引き受けることしかできないユーザーと、AIが使うロール、そのアクセスキーです。不要になったらスタックを削除すれば全部消えます。',
    permissions: [{ id: 'assume-role', name: 'ロールの権限でAWSを利用', description: '登録したロールに付けた権限の範囲で、AWSを操作できます。渡すのはロールの一時的な認証情報で、長期のアクセスキーは渡しません。', restrictions: '一時認証情報の有効期間はAIの要求とロールの設定で決まります (指定がなければAWSの既定)。ロールの権限はAWS側で管理します。' }],
    deliver: credentials => ({ env: 'AWS_SECRET_ACCESS_KEY', environment: { AWS_ACCESS_KEY_ID: credentials.details.session_access_key_id, AWS_SESSION_TOKEN: credentials.details.session_token, AWS_REGION: credentials.details.region, AWS_DEFAULT_REGION: credentials.details.region } }),
  };
}

// The adapter with no service of its own: the runtime declares the service, where the key is made,
// and the schema, whose field ids are the variables it receives. Foundation neither checks nor converts.
export function generic(client) {
  return {
    id: 'generic', service: null, label: 'キーを登録', register: 'paste', client, canReconnect: false, canRevoke: false, credentialType: 'api_key', declared: true,
    intro: 'サービスの設定画面で作成したキーを登録します。Foundationはキーの権限や有効性を検証しません。',
    instructions: 'AIが指定した値を受け付けます。Foundationは検証しません。',
    requestFields: [{ id: 'service', label: 'サービス' }, { id: 'site', label: 'キーの作成ページ', type: 'url' }],
    permissions: [{ id: 'key', name: 'キーの権限で利用', description: 'このキーで行える操作は、サービス側でキーに与えた権限のとおりです。Foundationはその内容を確認できません。', restrictions: '読み取り専用とは限りません。範囲を絞る場合は、サービス側で権限を制限したキーを作成してください。' }],
    matches: (permission, account, details) => !details || client.fieldsOf(details).every(id => account.scopes.includes('field:' + id)) && account.scopes.includes(client.serviceScope(details)),
    deliver: credentials => { const [first, ...rest] = credentials.details.fields; return { env: first, environment: Object.fromEntries(rest.map(id => [id, credentials.values[id]])) }; },
  };
}

export class Adapters {
  constructor(adapters) { this.adapters = new Map(adapters.map(adapter => [adapter.id, adapter])); }
  get(id) {
    const adapter = this.adapters.get(id);
    if (!adapter) fail(400, 'invalid_adapter', '対応している接続方法を指定してください。');
    return adapter;
  }
  ids() { return [...this.adapters.keys()]; }
  permission(id, permissionId) {
    const permission = this.get(id).permissions.find(value => value.id === permissionId);
    if (!permission) fail(400, 'invalid_permission', '利用する権限を選んでください。');
    return permission;
  }
  // What the runtime declared on a request, checked by the adapter that reads it. Only the generic adapter takes any.
  details(id, input) { const adapter = this.get(id); return adapter.declared ? adapter.client.details(input) : {}; }
  matches(adapterId, permissionId, account, details) {
    const adapter = this.get(adapterId);
    return Boolean(account) && account.adapter === adapterId && (adapter.matches ? adapter.matches(permissionId, account, details) : true);
  }
  permissionOf(account) { const adapter = this.get(account.adapter); return adapter.permissions.find(permission => this.matches(adapter.id, permission.id, account)); }
  // What the registration form shows and accepts: the adapter's own schema, or for the generic adapter the declared one.
  form(id, details) {
    const adapter = this.get(id);
    if (adapter.declared) return details ? { schema: adapter.client.schema(details), links: [{ label: details.site, href: details.site, declared: true }] } : null;
    return adapter.schema ? { schema: adapter.schema, links: adapter.links || [] } : null;
  }
  deliver(id, credentials, account) {
    const { env = null, file = null, environment = {} } = this.get(id).deliver(credentials, account);
    return { token_env: env, token_file: file, environment };
  }
  describe(id) {
    const adapter = this.get(id);
    return { id, service: adapter.service ? { id: adapter.service, ...SERVICES[adapter.service] } : null, label: adapter.label, register: adapter.register, available: adapter.client.enabled,
      intro: adapter.intro || '', permissions: adapter.permissions, request_fields: adapter.requestFields || [], declared: Boolean(adapter.declared),
      ...(adapter.instructions ? { instructions: adapter.instructions } : {}), ...(adapter.note ? { note: adapter.note } : {}),
      ...(this.form(id) ? { form: this.form(id) } : {}),
      can_reconnect: adapter.canReconnect !== false, can_revoke: adapter.canRevoke !== false, credential_type: adapter.credentialType || 'oauth2_access_token' };
  }
}
