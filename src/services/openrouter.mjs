import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const OPENROUTER_API = 'https://openrouter.ai/api/v1';
export const OPENROUTER_DOCS = 'https://openrouter.ai/docs/api/api-reference/overview';
export const OPENROUTER_SCOPE = 'openrouter:api-key';
const hash = key => createHash('sha256').update(key).digest('hex');
const validKey = key => typeof key === 'string' && /^sk-or-v1-[A-Za-z0-9_-]{20,512}$/.test(key);
const invalidResponse = () => fail(502, 'service_response', 'OpenRouterからの応答を確認できませんでした。');

// PKCE returns a user-controlled API key, not a refreshable short-lived token.
// No completion, credit purchase, or management-key operation belongs here.
export class OpenRouterClient {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'openrouter_unavailable', '現在OpenRouterに接続できません。'); }
  authorize({ state, verifier, redirectUri }) {
    this.check();
    // OpenRouter preserves the callback URL, but does not document a separate
    // OAuth state parameter. Bind our state to that URL and the user's session.
    const callback = new URL(redirectUri);
    callback.searchParams.set('state', state);
    const url = new URL('https://openrouter.ai/auth');
    url.search = new URLSearchParams({ callback_url: callback.href, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', key_label: 'Foundation' }).toString();
    return url.href;
  }
  async request(path, options = {}) {
    let response;
    try { response = await this.fetcher(OPENROUTER_API + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'OpenRouterに接続できませんでした。時間をおいて再度お試しください。'); }
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) fail(409, 'reconnect_required', 'OpenRouterのキーを確認するか、新しく登録してください。');
      if (response.status === 429) fail(503, 'service_rate_limit', 'OpenRouterの利用上限に達しました。時間をおいて再度お試しください。');
      fail(502, 'service_unavailable', 'OpenRouterで処理を完了できませんでした。');
    }
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    return data;
  }
  async inspect(key) {
    if (!validKey(key)) invalidResponse();
    const { data } = await this.request('/key', { headers: { authorization: 'Bearer ' + key } });
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    // Never import an account-wide management key through this connector.
    if (data.is_management_key !== false || data.is_provisioning_key === true) fail(409, 'scope_mismatch', '管理用ではなく、通常のAPIキーで接続してください。');
    for (const field of ['limit', 'limit_remaining']) if (data[field] !== null && (!Number.isFinite(data[field]) || (field === 'limit' && data[field] < 0))) invalidResponse();
    if (data.limit_reset !== null && !['daily', 'weekly', 'monthly'].includes(data.limit_reset)) invalidResponse();
    if (typeof data.include_byok_in_limit !== 'boolean') invalidResponse();
    let expiresAt = null;
    if (data.expires_at != null) {
      if (typeof data.expires_at !== 'string' || !Number.isFinite(Date.parse(data.expires_at))) invalidResponse();
      expiresAt = Date.parse(data.expires_at);
      if (expiresAt <= Date.now()) fail(409, 'reconnect_required', 'OpenRouterのキーは期限切れです。新しく接続してください。');
    }
    return { access_token: key, credential_type: 'api_key', expires_at: expiresAt, expiry_known: Object.hasOwn(data, 'expires_at'), scopes: [OPENROUTER_SCOPE],
      details: { key_hash: hash(key), limit: data.limit, limit_remaining: data.limit_remaining, limit_reset: data.limit_reset, include_byok_in_limit: data.include_byok_in_limit, checked_at: Date.now() } };
  }
  async exchange({ code, verifier }, previous) {
    this.check();
    if (previous) fail(400, 'new_connection_required', 'OpenRouterを新しく登録してください。');
    const result = await this.request('/auth/keys', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code, code_verifier: verifier, code_challenge_method: 'S256' }) });
    const secret = await this.inspect(result.key);
    // A connection identifies the authorized key, not an assumed email address.
    return { subject: 'key:' + secret.details.key_hash, secret };
  }
  async token(store, credential) {
    this.check();
    if (credential.status !== 'connected') fail(409, 'reconnect_required', 'OpenRouterのキーを確認するか、新しく登録してください。');
    try {
      const next = await this.inspect(store.secret(credential).access_token);
      if (credential.subject !== 'key:' + next.details.key_hash) invalidResponse();
      store.saveSecret(credential, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'scope_mismatch'].includes(error.code)) store.reconnectRequired(credential);
      throw error;
    }
  }
  facts(secret) {
    const detail = secret.details;
    return { label: 'キー ' + detail.key_hash.slice(0, 12), credential_type: 'api_key', expires_at: secret.expires_at, expiry_known: secret.expiry_known,
      management_url: 'https://openrouter.ai/keys/' + detail.key_hash,
      key_info: { limit: detail.limit, limit_remaining: detail.limit_remaining, limit_reset: detail.limit_reset, include_byok_in_limit: detail.include_byok_in_limit, checked_at: detail.checked_at } };
  }
}
