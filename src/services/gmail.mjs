import { createHash } from 'node:crypto';
import { fail } from '../errors.mjs';

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
  // What part of the mailbox a credential reaches. The two Gmail adapters each fix one.
  scope(range) {
    if (range === 'readonly') return READONLY_SCOPE;
    if (range === 'metadata') return METADATA_SCOPE;
    throw new Error('Unknown Gmail range: ' + range);
  }
  authorize({ state, verifier, redirectUri, range, email }) {
    this.check();
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: this.clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: this.scope(range), access_type: 'offline', prompt: 'consent select_account',
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
      if (data?.error === 'invalid_grant' || response.status === 401) fail(409, 'reconnect_required', 'Gmailの登録し直しが必要です。');
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
  grant(data, range, previous) {
    const requested = this.scope(range);
    const scopes = typeof data.scope === 'string' ? [...new Set(data.scope.trim().split(/\s+/))].sort() : previous?.scopes;
    const allowed = new Set([...IDENTITY_SCOPES, METADATA_SCOPE, ...(range === 'readonly' ? [READONLY_SCOPE] : [])]);
    if (!scopes?.includes(requested) || scopes.some((scope) => !allowed.has(scope))) fail(409, 'scope_mismatch', '選んだ読み取り範囲とGoogleの許可が一致しません。Google側の許可を確認してください。');
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 8192 || /[\r\n]/.test(data.access_token) || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 86400 || (data.token_type && (typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer'))) fail(502, 'service_response', 'Googleの認証応答を確認できませんでした。');
    const refreshToken = data.refresh_token || previous?.refresh_token;
    if (typeof refreshToken !== 'string' || !refreshToken || refreshToken.length > 8192) fail(409, 'refresh_missing', '継続利用の許可を取得できませんでした。もう一度Gmailを登録してください。');
    return { access_token: data.access_token, refresh_token: refreshToken, expires_at: Date.now() + data.expires_in * 1000, scopes };
  }
  async identity(accessToken) {
    const data = await this.request(GMAIL_API + '/users/me/profile?fields=emailAddress', { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.emailAddress !== 'string' || data.emailAddress.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.emailAddress)) fail(502, 'service_response', 'Gmailのアドレスを確認できませんでした。');
    return data.emailAddress.toLowerCase();
  }
  async exchange({ code, verifier, redirectUri, range }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 8192 || /[\r\n]/.test(data.access_token)) fail(502, 'service_response', 'Googleの認証応答を確認できませんでした。');
    // Verify identity before allowing reuse of an existing refresh token.
    const email = await this.identity(data.access_token);
    if (previous && previous.subject !== email) fail(409, 'account_changed', '登録し直すには同じGoogleアカウントを選んでください。');
    return { subject: email, secret: this.grant(data, range, previous?.secret) };
  }
  async token(existing, credential, force = false) {
    this.check();
    if (credential.status !== 'connected') fail(409, 'reconnect_required', 'Gmailの登録し直しが必要です。');
    if (!force && existing.expires_at > Date.now() + 60_000) return existing;
    const key = credential.id + ':' + credential.generation;
    if (this.pending.has(key)) return this.pending.get(key);
    const pending = (async () => {
      const data = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token });
      const next = this.grant(data, existing.scopes.includes(READONLY_SCOPE) ? 'readonly' : 'metadata', existing);
      if (JSON.stringify(next.scopes) !== JSON.stringify(existing.scopes.slice().sort())) fail(409, 'scope_mismatch', 'Googleの許可範囲が変わりました。Gmailを登録し直してください。');
      if (await this.identity(next.access_token) !== credential.subject) fail(409, 'account_changed', 'Gmailのアカウントが変わりました。登録を確認してください。');
      return next;
    })();
    this.pending.set(key, pending);
    try { return await pending; } finally { this.pending.delete(key); }
  }
  async revoke(secret) {
    this.check();
    let response;
    try {
      response = await this.fetcher('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: secret.refresh_token }), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'revoke_failed', 'Googleの許可を取り消せませんでした。この認証情報の受け渡しは停止しています。もう一度お試しください。'); }
    if (!response.ok) {
      let data; try { data = await response.json(); } catch {}
      if (!(response.status === 400 && data?.error === 'invalid_token')) fail(502, 'revoke_failed', 'Googleの許可を取り消せませんでした。この認証情報の受け渡しは停止しています。もう一度お試しください。');
    }
  }
}
