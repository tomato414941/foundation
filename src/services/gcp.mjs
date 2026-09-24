import { createHash } from 'node:crypto';
import { fail } from '../errors.mjs';

export const GCP_API = 'https://cloudresourcemanager.googleapis.com';
export const GCP_DOCS = 'https://docs.cloud.google.com/apis/docs/overview';
export const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';
export const GCP_SCOPES = ['openid', EMAIL_SCOPE, CLOUD_PLATFORM_SCOPE].sort();
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
const invalidResponse = () => fail(502, 'service_response', 'Google Cloudの認証応答を確認できませんでした。');
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[\x00-\x20\x7f]/.test(value);

// Cloud IAM determines resource access. OAuth scopes are reported, not treated as an IAM policy.
// Only short-lived access tokens leave this client; renewal stays with the connection.
export class GcpClient {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error('Both Foundation GCP client ID and client secret are required');
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId; this.clientSecret = clientSecret; this.fetcher = fetcher;
    this.pending = new Map();
  }
  check() { if (!this.enabled) fail(503, 'gcp_unavailable', '現在Google Cloudに接続できません。'); }
  authorize({ state, verifier, redirectUri, email }) {
    this.check();
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: this.clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: GCP_SCOPES.join(' '), access_type: 'offline', prompt: 'consent select_account',
      include_granted_scopes: 'false', state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
      // Google accepts the stable sub identifier as a login hint as well as an email address.
      ...(email ? { login_hint: email } : {}),
    }).toString();
    return url.href;
  }
  async call(url, options = {}) {
    try { return await this.fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Googleに接続できませんでした。時間をおいて再度お試しください。'); }
  }
  async request(url, options) {
    const response = await this.call(url, options);
    let data;
    try { data = await response.json(); } catch {}
    if (!response.ok) {
      if (data?.error === 'invalid_grant' || response.status === 401) fail(409, 'reconnect_required', 'Google Cloudに接続し直してください。');
      if (response.status === 429) fail(503, 'service_rate_limit', 'Googleの利用上限に達しました。時間をおいて再度お試しください。');
      fail(502, 'service_unavailable', 'Googleで処理を完了できませんでした。');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    return data;
  }
  tokenRequest(values) {
    this.check();
    return this.request(TOKEN_URL, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, ...values }) });
  }
  grant(data, previous) {
    if (!validToken(data.access_token) || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 86400
      || (data.token_type !== undefined && (typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer'))) invalidResponse();
    let scopes;
    if (data.scope === undefined && previous) scopes = previous.scopes;
    else {
      if (typeof data.scope !== 'string' || !data.scope.trim() || data.scope.length > 8192 || /[^\x20-\x21\x23-\x5b\x5d-\x7e]/.test(data.scope)) invalidResponse();
      scopes = [...new Set(data.scope.trim().split(/ +/).map(scope => scope === 'email' ? EMAIL_SCOPE : scope))].sort();
    }
    const refreshToken = data.refresh_token === undefined ? previous?.refresh_token : data.refresh_token;
    if (!refreshToken) fail(409, 'refresh_missing', '継続利用の許可を取得できませんでした。Google Cloudに接続し直してください。');
    if (!validToken(refreshToken)) invalidResponse();
    return { access_token: data.access_token, refresh_token: refreshToken, scopes, expires_at: Date.now() + data.expires_in * 1000 };
  }
  async identity(accessToken) {
    const data = await this.request(USERINFO_URL, { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.sub !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(data.sub)
      || (data.email !== undefined && (typeof data.email !== 'string' || data.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.email)))
      || (data.email_verified !== undefined && typeof data.email_verified !== 'boolean')) invalidResponse();
    // Email is optional display metadata, never the identity used to pin the account.
    return { subject: data.sub, email: data.email?.toLowerCase() || '', email_verified: data.email_verified === true, checked_at: Date.now() };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (!validToken(data.access_token)) invalidResponse();
    const identity = await this.identity(data.access_token);
    // A previous refresh token may only be reused after verifying the stable Google account ID.
    if (previous && previous.subject !== identity.subject) fail(409, 'account_changed', '接続し直すには同じGoogleアカウントを選んでください。');
    return { subject: identity.subject, secret: { ...this.grant(data, previous?.secret), identity } };
  }
  async token(existing, credential, force = false) {
    this.check();
    if (credential.status !== 'connected') fail(409, 'reconnect_required', 'Google Cloudに接続し直してください。');
    if (!force && existing.expires_at > Date.now() + 60_000) return existing;
    const key = credential.id + ':' + credential.generation;
    if (this.pending.has(key)) return this.pending.get(key);
    const pending = (async () => {
      const next = this.grant(await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
      const identity = await this.identity(next.access_token);
      if (identity.subject !== credential.subject) fail(409, 'account_changed', 'Google Cloudのアカウントが変わりました。接続を確認してください。');
      return { ...next, identity };
    })();
    this.pending.set(key, pending);
    try { return await pending; } finally { this.pending.delete(key); }
  }
  facts(secret) {
    return { label: secret.identity.email || secret.identity.subject, account_id: secret.identity.subject, email_verified: secret.identity.email_verified, scopes: secret.scopes,
      missing_scopes: GCP_SCOPES.filter(scope => !secret.scopes.includes(scope)),
      additional_scopes: secret.scopes.filter(scope => !GCP_SCOPES.includes(scope)),
      iam_checked: false, checked_at: secret.identity.checked_at };
  }
  async revoke(secret) {
    this.check();
    let response;
    try { response = await this.call('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: secret.refresh_token }) }); }
    catch { fail(502, 'revoke_failed', 'Google側の許可を取り消せませんでした。'); }
    if (!response.ok) {
      let data; try { data = await response.json(); } catch {}
      if (!(response.status === 400 && data?.error === 'invalid_token')) fail(502, 'revoke_failed', 'Google側の許可を取り消せませんでした。');
    }
  }
}
