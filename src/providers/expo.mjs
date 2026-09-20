import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const EXPO_API = 'https://api.expo.dev/graphql';
export const EXPO_DOCS = 'https://docs.expo.dev/accounts/programmatic-access/';
export const EXPO_TOKENS = 'https://expo.dev/settings/access-tokens';
export const EXPO_SCOPE = 'expo:access-token';
const digest = token => createHash('sha256').update(token).digest('hex');
const identityQuery = 'query FoundationIdentity { meActor { __typename id ... on UserActor { username } ... on Robot { firstName } } }';
const invalidResponse = () => fail(502, 'provider_response', 'Expoからの応答を確認できませんでした。');

// Import only official access tokens. Browser session secrets are a different
// credential and must never be passed to EAS CLI as EXPO_TOKEN.
export class ExpoProvider {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'expo_unavailable', '現在Expoに接続できません。'); }
  async inspect(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9._~-]{20,1024}$/.test(token)) fail(400, 'invalid_credential', 'Expoで発行したアクセストークンを入力してください。');
    let response;
    try {
      response = await this.fetcher(EXPO_API, { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
        body: JSON.stringify({ query: identityQuery }), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'provider_unavailable', 'Expoに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 401 || response.status === 403) fail(409, 'reconnect_required', 'トークンが無効か、利用できません。Expoのトークン管理画面で確認してください。');
    if (response.status === 429) fail(503, 'provider_rate_limit', 'Expoへの確認が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'provider_unavailable', 'Expoで処理を完了できませんでした。');
    let result;
    try { result = await response.json(); } catch { invalidResponse(); }
    if (!result || typeof result !== 'object' || Array.isArray(result)) invalidResponse();
    if (result.errors !== undefined && !Array.isArray(result.errors)) invalidResponse();
    if (result.errors?.length) {
      if (result.errors.some(error => ['UNAUTHENTICATED', 'FORBIDDEN'].includes(error?.extensions?.code))) fail(409, 'reconnect_required', 'トークンが無効か、利用できません。Expoのトークン管理画面で確認してください。');
      invalidResponse();
    }
    const actor = result.data?.meActor;
    if (actor === null) fail(409, 'reconnect_required', 'このトークンでExpoのアカウントを確認できませんでした。');
    if (!actor || typeof actor.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(actor.id) || !['User', 'SSOUser', 'Robot'].includes(actor.__typename)) invalidResponse();
    const label = actor.__typename === 'Robot' ? actor.firstName : actor.username;
    if (typeof label !== 'string' || !label.trim() || label.length > 256 || /[\x00-\x1f\x7f]/.test(label)) invalidResponse();
    return { access_token: token, credential_type: 'api_key', expires_at: null, expiry_known: false, scopes: [EXPO_SCOPE],
      details: { token_hash: digest(token), actor_id: actor.id, label, actor_type: actor.__typename, checked_at: Date.now() } };
  }
  async importToken({ token, mode }) {
    this.check();
    if (mode !== 'access-token') fail(400, 'invalid_scope', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token);
    return { email: 'token:' + credentials.details.token_hash, credentials };
  }
  async token(store, account) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'Expoでトークンを確認し、新しい接続を追加してください。');
    try {
      const previous = store.secrets(account), next = await this.inspect(previous.access_token);
      if (account.email !== 'token:' + next.details.token_hash || previous.details.actor_id !== next.details.actor_id) invalidResponse();
      store.saveCredentials(account, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    return { label: credentials.details.label + (credentials.details.actor_type === 'Robot' ? ' (Robot)' : ''), credential_type: 'api_key',
      expires_at: null, expiry_known: false, management_url: EXPO_TOKENS };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'トークンの無効化はExpoのトークン管理画面で行ってください。'); }
}
