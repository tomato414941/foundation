import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const SUPABASE_API = 'https://api.supabase.com';
export const SUPABASE_DOCS = 'https://supabase.com/docs/reference/api/introduction';
export const SUPABASE_TOKENS = 'https://supabase.com/dashboard/account/tokens';
export const SUPABASE_SCOPE = 'supabase:access-token';
const digest = token => createHash('sha256').update(token).digest('hex');
const invalidResponse = () => fail(502, 'service_response', 'Supabaseからの応答を確認できませんでした。');
const text = (value, max) => typeof value === 'string' && value.trim() && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);

// Personal access tokens for the Management API and the Supabase CLI. The
// token is created by the user on the dashboard and pasted; Foundation checks
// it against /v1/profile so the connection shows who it belongs to.
export class SupabaseClient {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'supabase_unavailable', '現在Supabaseに接続できません。'); }
  async request(path, token) {
    let response;
    try { response = await this.fetcher(SUPABASE_API + path, { headers: { authorization: 'Bearer ' + token }, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Supabaseに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 401 || response.status === 403) fail(409, 'reconnect_required', 'トークンが無効か、失効しています。Supabaseのトークン管理画面で確認してください。');
    if (response.status === 429) fail(503, 'service_rate_limit', 'Supabaseへの確認が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'service_unavailable', 'Supabaseで処理を完了できませんでした。');
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    return data;
  }
  async inspect(token) {
    if (typeof token !== 'string' || !/^sbp_[A-Za-z0-9]{20,128}$/.test(token)) fail(400, 'invalid_credential', 'Supabaseのアクセストークン (sbp_ で始まる文字列) を確認してください。');
    const profile = await this.request('/v1/profile', token);
    if (!profile || typeof profile !== 'object' || Array.isArray(profile) || !text(profile.username, 254) || !text(profile.primary_email, 254) || !text(profile.gotrue_id, 128)) invalidResponse();
    const organizations = await this.request('/v1/organizations', token);
    if (!Array.isArray(organizations) || organizations.some(item => !item || !text(item.slug, 128) || !text(item.name, 256))) invalidResponse();
    return { access_token: token, credential_type: 'api_key', expires_at: null, expiry_known: false, scopes: [SUPABASE_SCOPE],
      details: { token_hash: digest(token), user_id: profile.gotrue_id, email: profile.primary_email.toLowerCase(), username: profile.username, organizations: organizations.map(item => ({ slug: item.slug, name: item.name })), checked_at: Date.now() } };
  }
  async importToken({ values, permission }) {
    const { token } = values;
    this.check();
    if (permission !== 'access-token') fail(400, 'invalid_permission', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token);
    return { subject: 'token:' + credentials.details.token_hash, credentials };
  }
  async token(store, account) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'Supabaseでトークンを確認し、新しい接続を追加してください。');
    try {
      const previous = store.secrets(account), next = await this.inspect(previous.access_token);
      if (account.subject !== 'token:' + next.details.token_hash || previous.details.user_id !== next.details.user_id) invalidResponse();
      store.saveCredentials(account, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: detail.email, credential_type: 'api_key', expires_at: null, expiry_known: false, management_url: SUPABASE_TOKENS,
      key_info: null, organizations: detail.organizations, checked_at: detail.checked_at };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'トークンの無効化はSupabaseのトークン管理画面で行ってください。'); }
}
