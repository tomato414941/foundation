import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const METADATA_SCOPE = 'https://www.googleapis.com/auth/gmail.metadata';
export const READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
export const GMAIL_API = 'https://gmail.googleapis.com/gmail/v1';
export const GMAIL_DOCS = 'https://developers.google.com/workspace/gmail/api/reference/rest';
const IDENTITY_SCOPES = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'];
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

export class GmailClient {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error('Both Foundation Google client ID and client secret are required');
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.fetcher = fetcher;
    this.pending = new Map();
  }
  check() { if (!this.enabled) fail(503, 'gmail_unavailable', '現在Gmailに接続できません。'); }
  scope(permission) {
    if (permission === 'readonly') return READONLY_SCOPE;
    if (permission === 'metadata') return METADATA_SCOPE;
    fail(400, 'invalid_permission', '読み取り範囲を選んでください。');
  }
  authorize({ state, verifier, redirectUri, permission, email }) {
    this.check();
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: this.clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: this.scope(permission), access_type: 'offline', prompt: 'consent select_account',
      include_granted_scopes: 'false', state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
      ...(email ? { login_hint: email } : {}),
    }).toString();
    return url.href;
  }
  async request(url, options = {}) {
    let response;
    try { response = await this.fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Googleに接続できませんでした。時間をおいて再度お試しください。'); }
    let data;
    try { data = await response.json(); } catch { data = null; }
    if (!response.ok) {
      if (data?.error === 'invalid_grant' || response.status === 401) fail(409, 'reconnect_required', 'Gmailへの再接続が必要です。');
      if (response.status === 429) fail(503, 'service_rate_limit', 'Googleの利用上限に達しました。時間をおいて再度お試しください。');
      fail(502, 'service_unavailable', 'Googleで処理を完了できませんでした。');
    }
    if (!data || typeof data !== 'object') fail(502, 'service_response', 'Googleからの応答を確認できませんでした。');
    return data;
  }
  async tokenRequest(values) {
    this.check();
    return this.request(TOKEN_URL, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, ...values }) });
  }
  credentials(data, permission, previous) {
    const requested = this.scope(permission);
    const scopes = typeof data.scope === 'string' ? [...new Set(data.scope.trim().split(/\s+/))].sort() : previous?.scopes;
    const allowed = new Set([...IDENTITY_SCOPES, METADATA_SCOPE, ...(permission === 'readonly' ? [READONLY_SCOPE] : [])]);
    if (!scopes?.includes(requested) || scopes.some((scope) => !allowed.has(scope))) fail(409, 'scope_mismatch', '選んだ読み取り範囲とGoogleの許可が一致しません。Google側の許可を確認してください。');
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 8192 || /[\r\n]/.test(data.access_token) || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 86400 || (data.token_type && (typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer'))) fail(502, 'service_response', 'Googleの認証応答を確認できませんでした。');
    const refreshToken = data.refresh_token || previous?.refresh_token;
    if (typeof refreshToken !== 'string' || !refreshToken || refreshToken.length > 8192) fail(409, 'refresh_missing', '継続利用の許可を取得できませんでした。もう一度Gmailを接続してください。');
    return { access_token: data.access_token, refresh_token: refreshToken, expires_at: Date.now() + data.expires_in * 1000, scopes };
  }
  async identity(accessToken) {
    const data = await this.request(GMAIL_API + '/users/me/profile?fields=emailAddress', { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.emailAddress !== 'string' || data.emailAddress.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.emailAddress)) fail(502, 'service_response', 'Gmailのアドレスを確認できませんでした。');
    return data.emailAddress.toLowerCase();
  }
  async exchange({ code, verifier, redirectUri, permission }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 8192 || /[\r\n]/.test(data.access_token)) fail(502, 'service_response', 'Googleの認証応答を確認できませんでした。');
    // Verify identity before allowing reuse of an existing refresh token.
    const email = await this.identity(data.access_token);
    if (previous && previous.subject !== email) fail(409, 'account_changed', '再接続には同じGoogleアカウントを選んでください。');
    return { subject: email, credentials: this.credentials(data, permission, previous?.credentials) };
  }
  async token(store, account, force = false) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'Gmailへの再接続が必要です。');
    const existing = store.secrets(account);
    if (!force && existing.expires_at > Date.now() + 60_000) return existing;
    const key = account.id + ':' + account.generation;
    if (this.pending.has(key)) return this.pending.get(key);
    const pending = (async () => {
      try {
        const data = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token });
        const next = this.credentials(data, account.scopes.includes(READONLY_SCOPE) ? 'readonly' : 'metadata', existing);
        if (JSON.stringify(next.scopes) !== JSON.stringify(account.scopes.slice().sort())) fail(409, 'scope_mismatch', 'Googleの許可範囲が変わりました。Gmailを再接続してください。');
        if (await this.identity(next.access_token) !== account.subject) fail(409, 'account_changed', 'Gmailのアカウントが変わりました。接続を確認してください。');
        store.saveCredentials(account, next);
        return next;
      } catch (error) {
        if (error instanceof HttpError && ['reconnect_required', 'scope_mismatch', 'account_changed', 'refresh_missing'].includes(error.code)) store.reconnectRequired(account);
        throw error;
      }
    })();
    this.pending.set(key, pending);
    try { return await pending; } finally { this.pending.delete(key); }
  }
  async revoke(credentials) {
    this.check();
    let response;
    try {
      response = await this.fetcher('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: credentials.refresh_token }), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'revoke_failed', 'Googleの許可を取り消せませんでした。接続は停止しています。もう一度お試しください。'); }
    if (!response.ok) {
      let data; try { data = await response.json(); } catch {}
      if (!(response.status === 400 && data?.error === 'invalid_token')) fail(502, 'revoke_failed', 'Googleの許可を取り消せませんでした。接続は停止しています。もう一度お試しください。');
    }
  }
}
