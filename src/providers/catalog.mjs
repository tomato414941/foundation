import { fail } from '../errors.mjs';
import { GMAIL_API, GMAIL_DOCS, METADATA_SCOPE, READONLY_SCOPE } from './gmail.mjs';
import { OPENROUTER_API, OPENROUTER_DOCS, OPENROUTER_SCOPE } from './openrouter.mjs';
import { EXPO_API, EXPO_DOCS, EXPO_SCOPE, EXPO_SESSION_SCOPE, EXPO_TOKENS } from './expo.mjs';
import { APIKEY_SCOPE } from './apikey.mjs';
import { SUPABASE_API, SUPABASE_DOCS, SUPABASE_SCOPE, SUPABASE_TOKENS } from './supabase.mjs';
import { APPLE_API, APPLE_DOCS, APPLE_KEYS, APPLE_SCOPE } from './apple.mjs';
import { AWS_DOCS, AWS_KEYS, AWS_SCOPE, AWS_TEMPLATE_PATH, quickCreateUrl } from './aws.mjs';
import { CLOUDFLARE_API, CLOUDFLARE_DOCS, CLOUDFLARE_SCOPE, CLOUDFLARE_TOKENS } from './cloudflare.mjs';

// Each integration supplies its authentication client and permission descriptions.
// Request creation, user approval and runtime authentication do not depend on Gmail.
export function gmailConnection(client) {
  return {
    id: 'gmail', name: 'Gmail', connectLabel: 'Googleで接続', client, tokenEnv: 'GOOGLE_OAUTH_ACCESS_TOKEN',
    icon: 'mail', intro: 'Googleアカウントと読み取り範囲を選べます。', managementUrl: 'https://myaccount.google.com/connections',
    api: { base_url: GMAIL_API, documentation_url: GMAIL_DOCS },
    permissions: [
      { id: 'readonly', name: 'メールの読み取り', description: '本文・添付ファイルを含む、すべてのメール', restrictions: '送信・変更・削除は許可しません。' },
      { id: 'metadata', name: '件名・差出人などの読み取り', description: '本文・添付ファイルは対象外', restrictions: '本文の取得・送信・変更・削除は許可しません。' },
    ],
    matches(mode, account) {
      return account && account.provider === 'gmail' && (mode === 'readonly' ? account.scopes.includes(READONLY_SCOPE) : account.scopes.includes(METADATA_SCOPE) && !account.scopes.includes(READONLY_SCOPE));
    },
  };
}

export function openrouterConnection(client) {
  return {
    id: 'openrouter', name: 'OpenRouter', connectLabel: 'OpenRouterで接続', client, icon: 'network', canReconnect: false, canRevoke: false, tokenEnv: 'OPENROUTER_API_KEY',
    intro: 'OpenRouterでログインし、接続用のキーを作成します。', managementUrl: 'https://openrouter.ai/keys', credentialType: 'api_key',
    api: { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS },
    permissions: [{ id: 'api-key', name: 'APIキーの利用', description: 'このキーの権限でOpenRouter APIを利用できます。モデルの実行は課金を伴う場合があります。', restrictions: '利用上限と有効期限はOpenRouter側の設定が適用されます。読み取り専用のキーではありません。' }],
    matches(mode, account) { return mode === 'api-key' && account?.provider === 'openrouter' && account.scopes.length === 1 && account.scopes[0] === OPENROUTER_SCOPE; },
  };
}

export function expoConnection(client) {
  return {
    id: 'expo', name: 'Expo', connectLabel: client.sessionLoginEnabled ? 'Expoにログイン' : 'Expoのトークンを登録', client, icon: 'device', canReconnect: false, canRevoke: false, tokenEnv: credentials => credentials.credential_type === 'expo_session' ? null : 'EXPO_TOKEN',
    intro: client.sessionLoginEnabled ? 'Expoにログインして接続します。' : 'Expoで発行したアクセストークンを登録します。', managementUrl: EXPO_TOKENS, credentialType: 'api_key',
    connectionMethod: client.sessionLoginEnabled ? 'password' : 'token', tokenSetup: { url: EXPO_TOKENS, label: 'アクセストークン',
      instructions: 'Expoにログインして「Create Token」から、この接続専用のトークンを作成してください。名前は「Foundation」など、用途がわかるものにします。' },
    api: { base_url: EXPO_API, documentation_url: EXPO_DOCS },
    permissions: [...(client.sessionLoginEnabled ? [{ id: 'session', name: 'Expoアカウントの利用', description: 'このAIに、Expoであなたと同じ権限での操作を許可します。ビルド・公開など、課金を伴う操作も含みます。', restrictions: '接続を解除すると、この接続のログインセッションを無効にできます。', connection_method: 'password' }] : []), { id: 'access-token', name: 'トークンの権限でExpoを利用', connection_method: 'token', connect_label: 'Expoのトークンを登録',
      description: '個人用トークンは、本人がアクセスできるすべてのアカウント・組織で操作できます。ビルドなどは課金を伴う場合があります。',
      restrictions: '読み取り専用ではありません。対象や操作を絞る場合は、Expoで権限を制限したRobotのトークンを使ってください。' }],
    matches(mode, account) { return account?.provider === 'expo' && account.scopes.length === 1 && (mode === 'access-token' ? account.scopes[0] === EXPO_SCOPE : mode === 'session' && client.sessionLoginEnabled && account.scopes[0] === EXPO_SESSION_SCOPE); },
  };
}

export function cloudflareConnection(client) {
  return {
    id: 'cloudflare', name: 'Cloudflare', connectLabel: 'Cloudflareのトークンを登録', client, icon: 'cloud', canReconnect: false, canRevoke: false,
    intro: 'APIトークンでR2に接続します。', managementUrl: CLOUDFLARE_TOKENS, credentialType: 'api_key', connectionMethod: 'token', tokenEnv: 'CLOUDFLARE_API_TOKEN',
    tokenSetup: { url: CLOUDFLARE_TOKENS, label: 'APIトークン',
      instructions: '「Create Token」→「Create Custom Token」で、Account → Workers R2 Storage → Read を選び、対象アカウントを1つに限定してください。不要な権限は追加せず、有効期限を設定してください。',
      note: '登録時にR2の一覧へのアクセスを確認します。トークンの権限全体は確認・制限しません。',
      fields: [{ id: 'account_id', label: 'アカウントID', max_length: 32, pattern: '[a-fA-F0-9]{32}', help: 'CloudflareのR2画面にある「Account ID」をコピーしてください。' }] },
    api: { base_url: CLOUDFLARE_API, documentation_url: CLOUDFLARE_DOCS },
    permissions: [{ id: 'api-token', name: 'トークンの権限でCloudflareを利用', connection_method: 'token',
      description: 'APIトークンを登録し、指定したアカウントでR2の一覧を取得できるか確認します。',
      restrictions: '利用できる範囲はトークンに与えた全権限です。ここで指定するアカウントIDや用途では制限されません。読み取り専用のトークンを使ってください。' }],
    matches(mode, account) { return mode === 'api-token' && account?.provider === 'cloudflare' && account.scopes.length === 1 && account.scopes[0] === CLOUDFLARE_SCOPE; },
  };
}

export function supabaseConnection(client) {
  return {
    id: 'supabase', name: 'Supabase', connectLabel: 'Supabaseのトークンを登録', client, icon: 'database', canReconnect: false, canRevoke: false,
    intro: 'Supabaseで発行したアクセストークンを登録します。', managementUrl: SUPABASE_TOKENS, credentialType: 'api_key', connectionMethod: 'token', tokenEnv: 'SUPABASE_ACCESS_TOKEN',
    tokenSetup: { url: SUPABASE_TOKENS, label: 'アクセストークン', instructions: 'Supabaseにログインして「Generate new token」から、この接続専用のトークンを作成してください。名前は「Foundation」など、用途がわかるものにします。' },
    api: { base_url: SUPABASE_API, documentation_url: SUPABASE_DOCS },
    permissions: [{ id: 'access-token', name: 'アカウントの権限でSupabaseを利用', connection_method: 'token',
      description: 'アカウントがアクセスできるすべての組織とプロジェクトを、Management APIとCLIから操作できます。プロジェクトの作成・削除や設定変更も含みます。',
      restrictions: '読み取り専用ではありません。プロジェクトのデータベースのキー (anon / service_role) はこのトークンでは渡しません。' }],
    matches(mode, account) { return mode === 'access-token' && account?.provider === 'supabase' && account.scopes.length === 1 && account.scopes[0] === SUPABASE_SCOPE; },
  };
}

// App Store Connect API key for EAS: the .p8 travels as a file that exists only
// while the command runs; the identifiers travel as plain environment variables.
export function appleConnection(client) {
  return {
    id: 'apple', name: 'Apple', connectLabel: 'AppleのAPIキーを登録', client, icon: 'key', canReconnect: false, canRevoke: false,
    intro: 'App Store ConnectのAPIキー (.p8) と識別情報を登録します。', managementUrl: APPLE_KEYS, credentialType: 'private_key', connectionMethod: 'token',
    tokenEnv: null,
    tokenFile: credentials => ({ env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey_' + credentials.details.key_id + '.p8' }),
    environment: credentials => ({ EXPO_ASC_KEY_ID: credentials.details.key_id, EXPO_ASC_ISSUER_ID: credentials.details.issuer_id, EXPO_APPLE_TEAM_ID: credentials.details.team_id, EXPO_APPLE_TEAM_TYPE: credentials.details.team_type }),
    tokenSetup: { url: APPLE_KEYS, label: 'APIキー (.p8 の内容)', multiline: true, link_label: 'App Store Connect の「統合」を開く',
      instructions: '「ユーザーとアクセス」→「統合」→「App Store Connect API」で「チームキー」を作成し、ダウンロードした .p8 ファイルの中身を貼り付けてください。EASの署名準備には Admin の役割が必要です。',
      note: '登録時にAppleへ1回だけ読み取りで問い合わせ、キーが有効か確認します。証明書やプロファイルの作成はEASが行い、Foundationは関与しません。',
      fields: [
        { id: 'key_id', label: 'Key ID', max_length: 10, pattern: '[A-Za-z0-9]{10}', help: 'キー一覧に表示される10桁のID。' },
        { id: 'issuer_id', label: 'Issuer ID', max_length: 36, pattern: '[0-9a-fA-F-]{36}', help: 'キー一覧の上部に表示されるID。' },
        { id: 'team_id', label: 'Team ID', max_length: 10, pattern: '[A-Za-z0-9]{10}', help: 'Apple Developerの「メンバーシップ」に表示される10桁のID。' },
        { id: 'team_type', label: 'チーム種別', options: [['INDIVIDUAL', '個人 (Individual)'], ['COMPANY_OR_ORGANIZATION', '法人・組織 (Company / Organization)'], ['IN_HOUSE', '社内配布 (In-House)']], help: 'Apple Developer Program の契約種別。' },
      ] },
    api: { base_url: APPLE_API, documentation_url: APPLE_DOCS },
    permissions: [{ id: 'api-key', name: 'App Store Connect APIキーの権限でAppleを利用', connection_method: 'token',
      description: 'このキーにAppleで与えた役割の範囲で、アプリID・端末・証明書・プロビジョニングプロファイルの作成や更新ができます。',
      restrictions: '読み取り専用ではありません。Team API キーは単一アプリに限定できません。' }],
    matches(mode, account) { return mode === 'api-key' && account?.provider === 'apple' && account.scopes.length === 1 && account.scopes[0] === APPLE_SCOPE; },
  };
}

// AWS: Foundation keeps an IAM user key and issues temporary credentials for one
// role on every exec. Duration is the runtime's request and AWS's decision.
export function awsConnection(client, { templateUrl = '', region = 'ap-northeast-1' } = {}) {
  const quickCreate = quickCreateUrl(templateUrl, region);
  return {
    id: 'aws', name: 'AWS', connectLabel: 'AWSのアクセスキーを登録', client, icon: 'cloud', canReconnect: false, canRevoke: false, credentialType: 'api_key', connectionMethod: 'token',
    intro: 'IAMユーザーのアクセスキーと、AIに使わせるロールを登録します。AIには一時的な認証情報だけを渡します。', managementUrl: AWS_KEYS,
    tokenEnv: 'AWS_SECRET_ACCESS_KEY',
    environment: credentials => ({ AWS_ACCESS_KEY_ID: credentials.details.session_access_key_id, AWS_SESSION_TOKEN: credentials.details.session_token, AWS_REGION: credentials.details.region, AWS_DEFAULT_REGION: credentials.details.region }),
    tokenSetup: { url: quickCreate || AWS_TEMPLATE_PATH, label: 'シークレットアクセスキー', step_label: 'AWSにFoundation用のユーザーとロールを作る', link_label: quickCreate ? 'AWS で作成する' : '定義ファイルをダウンロード',
      instructions: quickCreate
        ? 'ボタンを押すと、AWSのCloudFormationに「Foundation用のユーザーとロール」を作る画面が開きます。権限の範囲を選び、確認欄にチェックして「スタックの作成」を押してください。完了後、「出力」タブに出る4つの値を下に貼り付けます。'
        : '定義ファイルをダウンロードし、AWSコンソールの CloudFormation で「スタックの作成」→「テンプレートファイルのアップロード」から投入してください。権限の範囲を選び、確認欄にチェックして作成します。完了後、「出力」タブに出る4つの値を下に貼り付けます。',
      note: '作られるのは、ロールを引き受けることしかできないユーザーと、AIが使うロール、そのアクセスキーです。不要になったらスタックを削除すれば全部消えます。登録時に GetCallerIdentity と AssumeRole を1回ずつ試して確認します。',
      fields: [
        { id: 'access_key_id', label: 'アクセスキーID', max_length: 20, pattern: 'AKIA[A-Z0-9]{16}', help: 'AKIA で始まる20文字。' },
        { id: 'role_arn', label: 'ロールARN', max_length: 200, pattern: 'arn:aws[a-z-]*:iam::[0-9]{12}:role/.+', help: 'AIに使わせるロール。権限はこのロールで絞ります。' },
        { id: 'region', label: 'リージョン', max_length: 32, pattern: '[a-z]{2}(-[a-z]+)+-[0-9]', help: '例: ap-northeast-1' },
      ] },
    api: { base_url: '', documentation_url: AWS_DOCS },
    permissions: [{ id: 'assume-role', name: 'ロールの権限でAWSを利用', connection_method: 'token',
      description: '登録したロールに付けた権限の範囲で、AWSを操作できます。渡すのはロールの一時的な認証情報で、長期のアクセスキーは渡しません。',
      restrictions: '一時認証情報の有効期間はAIの要求とロールの設定で決まります (指定がなければAWSの既定)。ロールの権限はAWS側で管理します。' }],
    matches(mode, account) { return mode === 'assume-role' && account?.provider === 'aws' && account.scopes.length === 1 && account.scopes[0] === AWS_SCOPE; },
  };
}

// Any service with a key the user can create themselves. The runtime supplies
// the service name, the key page and the variable name; the catalog only fixes
// the copy that must not come from the runtime.
export function apikeyConnection(client) {
  return {
    id: 'apikey', name: 'APIキー', connectLabel: 'キーを登録', client, icon: 'key', canReconnect: false, canRevoke: false, credentialType: 'api_key', connectionMethod: 'token',
    intro: 'サービスの設定画面で作成したキーを登録します。Foundationはキーの権限や有効性を検証しません。',
    tokenSetup: { label: 'APIキー', instructions: 'サービスの設定画面でこの接続専用のキーを作成し、貼り付けてください。名前は「Foundation」など、用途がわかるものにします。' },
    requestFields: [{ id: 'service', label: 'サービス' }, { id: 'site', label: 'キーの作成ページ', type: 'url' }, { id: 'env', label: '環境変数名', type: 'code' }],
    api: { base_url: '', documentation_url: '' },
    permissions: [{ id: 'key', name: 'キーの権限で利用', description: 'このキーで行える操作は、サービス側でキーに与えた権限のとおりです。Foundationはその内容を確認できません。', restrictions: '読み取り専用とは限りません。範囲を絞る場合は、サービス側で権限を制限したキーを作成してください。', connection_method: 'token' }],
    tokenEnv: (credentials) => client.tokenEnv(credentials),
    matches(mode, account, request) {
      if (mode !== 'key' || account?.provider !== 'apikey' || !account.scopes.includes(APIKEY_SCOPE)) return false;
      if (!request) return true;
      const expected = client.scopes(client.details(request.details));
      return expected.every(scope => account.scopes.includes(scope));
    },
  };
}

export class ProviderCatalog {
  constructor(definitions) {
    this.providers = new Map(definitions.map(definition => [definition.id, definition]));
  }
  get(id) {
    const provider = this.providers.get(id);
    if (!provider) fail(400, 'invalid_provider', '対応しているサービスを指定してください。');
    return provider;
  }
  permission(id, mode) {
    const permission = this.get(id).permissions.find(value => value.id === mode);
    if (!permission) fail(400, 'invalid_scope', '利用する権限を選んでください。');
    return permission;
  }
  details(id, input) {
    const provider = this.get(id);
    return provider.requestFields?.length ? provider.client.details(input) : {};
  }
  tokenEnv(id, credentials) {
    const value = this.get(id).tokenEnv;
    return typeof value === 'function' ? value(credentials) : value || null;
  }
  // How a runtime receives this credential: as a variable, as a file whose path is in a variable, plus plain identifiers.
  delivery(id, credentials) {
    const provider = this.get(id), call = value => typeof value === 'function' ? value(credentials) : value || null;
    return { token_env: this.tokenEnv(id, credentials), token_file: call(provider.tokenFile), environment: call(provider.environment) || {} };
  }
  describe(id) {
    const provider = this.get(id);
    return { id, name: provider.name, connect_label: provider.connectLabel, available: provider.client.enabled, permissions: provider.permissions, request_fields: provider.requestFields || [],
      icon: provider.icon || 'network', intro: provider.intro || '', api: provider.api, management_url: provider.managementUrl,
      connection_method: provider.connectionMethod || 'oauth', ...(provider.tokenSetup ? { token_setup: provider.tokenSetup } : {}),
      can_reconnect: provider.canReconnect !== false, can_revoke: provider.canRevoke !== false, credential_type: provider.credentialType || 'oauth2_access_token' };
  }
}
