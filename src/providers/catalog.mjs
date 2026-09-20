import { fail } from '../errors.mjs';
import { GMAIL_API, GMAIL_DOCS, METADATA_SCOPE, READONLY_SCOPE } from './gmail.mjs';
import { OPENROUTER_API, OPENROUTER_DOCS, OPENROUTER_SCOPE } from './openrouter.mjs';
import { EXPO_API, EXPO_DOCS, EXPO_SCOPE, EXPO_TOKENS } from './expo.mjs';

// Each integration supplies its authentication client and permission descriptions.
// Request creation, user approval and runtime authentication do not depend on Gmail.
export function gmailConnection(client) {
  return {
    id: 'gmail', name: 'Gmail', connectLabel: 'Googleで接続', client,
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
    id: 'openrouter', name: 'OpenRouter', connectLabel: 'OpenRouterで接続', client, icon: 'network', canReconnect: false, canRevoke: false,
    intro: 'OpenRouterでログインし、接続用のキーを作成します。', managementUrl: 'https://openrouter.ai/keys', credentialType: 'api_key',
    api: { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS },
    permissions: [{ id: 'api-key', name: 'APIキーの利用', description: 'このキーの権限でOpenRouter APIを利用できます。モデルの実行は課金を伴う場合があります。', restrictions: '利用上限と有効期限はOpenRouter側の設定が適用されます。読み取り専用のキーではありません。' }],
    matches(mode, account) { return mode === 'api-key' && account?.provider === 'openrouter' && account.scopes.length === 1 && account.scopes[0] === OPENROUTER_SCOPE; },
  };
}

export function expoConnection(client) {
  return {
    id: 'expo', name: 'Expo', connectLabel: 'Expoのトークンを登録', client, icon: 'device', canReconnect: false, canRevoke: false,
    intro: 'Expoで発行したアクセストークンを登録します。', managementUrl: EXPO_TOKENS, credentialType: 'api_key',
    connectionMethod: 'token', tokenSetup: { url: EXPO_TOKENS, label: 'アクセストークン',
      instructions: 'Expoにログインして「Create Token」から、この接続専用のトークンを作成してください。名前は「Foundation」など、用途がわかるものにします。' },
    api: { base_url: EXPO_API, documentation_url: EXPO_DOCS },
    permissions: [{ id: 'access-token', name: 'トークンの権限でExpoを利用',
      description: '個人用トークンは、本人がアクセスできるすべてのアカウント・組織で操作できます。ビルドなどは課金を伴う場合があります。',
      restrictions: '読み取り専用ではありません。対象や操作を絞る場合は、Expoで権限を制限したRobotのトークンを使ってください。' }],
    matches(mode, account) { return mode === 'access-token' && account?.provider === 'expo' && account.scopes.length === 1 && account.scopes[0] === EXPO_SCOPE; },
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
  describe(id) {
    const provider = this.get(id);
    return { id, name: provider.name, connect_label: provider.connectLabel, available: provider.client.enabled, permissions: provider.permissions,
      icon: provider.icon || 'network', intro: provider.intro || '', api: provider.api, management_url: provider.managementUrl,
      connection_method: provider.connectionMethod || 'oauth', ...(provider.tokenSetup ? { token_setup: provider.tokenSetup } : {}),
      can_reconnect: provider.canReconnect !== false, can_revoke: provider.canRevoke !== false, credential_type: provider.credentialType || 'oauth2_access_token' };
  }
}
