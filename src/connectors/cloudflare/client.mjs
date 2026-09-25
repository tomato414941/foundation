import { createHash } from 'node:crypto';
import { fail } from '../../errors.mjs';

export const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
export const CLOUDFLARE_DOCS = 'https://developers.cloudflare.com/api/';
export const CLOUDFLARE_SETTINGS = 'https://dash.cloudflare.com/?to=/profile/access-management/authorization';
// Cloudflare's self-managed clients use the dot-delimited IDs from GET /oauth/scopes.
export const CLOUDFLARE_SCOPES = ['user-details.read', 'account-settings.read', 'zone.read', 'dns.write', 'registrar-domains.admin', 'offline_access'].sort();
const OAUTH = 'https://dash.cloudflare.com/oauth2';
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[^\x21-\x7e]/.test(value);
const invalidResponse = () => fail(502, 'service_response', 'Cloudflareからの認証応答を確認できませんでした。');
const reconnect = () => fail(409, 'reconnect_required', 'Cloudflareの許可が失効しています。接続し直してください。');

export class CloudflareClient {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error('Both Foundation Cloudflare client ID and client secret are required');
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId; this.clientSecret = clientSecret; this.fetcher = fetcher;
  }
  check() { if (!this.enabled) fail(503, 'cloudflare_unavailable', '現在Cloudflareに接続できません。'); }
  authorize({ state, verifier, redirectUri }) {
    this.check();
    const url = new URL(OAUTH + '/auth');
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: CLOUDFLARE_SCOPES.join(' '), state, prompt: 'consent',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
    return url.href;
  }
  async call(url, options = {}) {
    this.check();
    try { return await this.fetcher(url, { ...options, headers: { accept: 'application/json', ...options.headers }, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Cloudflareに接続できませんでした。時間をおいて再度お試しください。'); }
  }
  async tokenRequest(values) {
    const response = await this.call(OAUTH + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...values, client_id: this.clientId, client_secret: this.clientSecret }) });
    let data;
    try { data = await response.json(); } catch {}
    if (!response.ok) {
      if (data?.error === 'invalid_grant' && values.grant_type === 'refresh_token') reconnect();
      if (data?.error === 'invalid_grant' && values.grant_type === 'authorization_code') fail(400, 'invalid_state', 'Cloudflareの接続をやり直してください。');
      if (response.status === 429) fail(503, 'service_rate_limit', 'Cloudflareの利用上限に達しました。時間をおいて再度お試しください。');
      if (response.status === 401 || data?.error === 'invalid_client') fail(503, 'cloudflare_unavailable', 'Cloudflareの接続設定を確認できませんでした。');
      fail(502, 'service_unavailable', 'Cloudflareで処理を完了できませんでした。');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    return data;
  }
  grant(data, previous) {
    if (!validToken(data.access_token) || typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer'
      || !Number.isSafeInteger(data.expires_in) || data.expires_in <= 0) invalidResponse();
    const expires_at = Date.now() + data.expires_in * 1000;
    if (!Number.isSafeInteger(expires_at) || expires_at > 8_640_000_000_000_000) invalidResponse();
    let scopes;
    if (data.scope === undefined && previous) scopes = previous.scopes;
    else {
      if (typeof data.scope !== 'string' || !data.scope.trim() || data.scope.length > 8192 || /[^\x20-\x21\x23-\x5b\x5d-\x7e]/.test(data.scope)) invalidResponse();
      scopes = [...new Set(data.scope.split(' ').filter(Boolean))].sort();
    }
    const refresh_token = data.refresh_token === undefined ? previous?.refresh_token : data.refresh_token;
    if (refresh_token === undefined) fail(409, 'refresh_missing', '継続利用の許可を取得できませんでした。Cloudflareに接続し直してください。');
    if (!validToken(refresh_token)) invalidResponse();
    return { client_id: this.clientId, access_token: data.access_token, refresh_token, expires_at, scopes };
  }
  async identity(accessToken) {
    const response = await this.call(CLOUDFLARE_API + '/user', { headers: { authorization: 'Bearer ' + accessToken } });
    if (response.status === 401) reconnect();
    if (response.status === 403) fail(409, 'scope_mismatch', 'Cloudflareアカウントを確認する権限が必要です。接続し直してください。');
    if (response.status === 429) fail(503, 'service_rate_limit', 'Cloudflareの利用上限に達しました。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'service_unavailable', 'Cloudflareでアカウントを確認できませんでした。');
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    const user = data?.result;
    if (data?.success !== true || !user || typeof user.id !== 'string' || !/^[a-f0-9]{32}$/.test(user.id)
      || typeof user.email !== 'string' || user.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(user.email)) invalidResponse();
    return { user_id: user.id, email: user.email, checked_at: Date.now() };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    const data = await this.tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri });
    // Reconnection obtains a fresh grant; never reuse another authorization's refresh token.
    const grant = this.grant(data), identity = await this.identity(grant.access_token);
    if (previous && previous.subject !== identity.user_id) fail(409, 'account_changed', '同じCloudflareアカウントで接続し直してください。');
    return { subject: identity.user_id, secret: { ...grant, identity } };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.client_id !== this.clientId || existing.identity.user_id !== subject) reconnect();
    if (existing.expires_at > Date.now() + 60_000) return existing;
    const data = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token });
    // The refresh grant is already bound to this client and user. Persist its rotated token
    // immediately, without a second network request that could lose it on failure.
    return { ...this.grant(data, existing), identity: existing.identity };
  }
  facts(secret) {
    return { label: secret.identity.email, user_id: secret.identity.user_id, scopes: secret.scopes,
      missing_scopes: CLOUDFLARE_SCOPES.filter(scope => !secret.scopes.includes(scope)),
      additional_scopes: secret.scopes.filter(scope => !CLOUDFLARE_SCOPES.includes(scope)),
      checked_at: secret.identity.checked_at };
  }
  async revoke(secret) {
    this.check();
    if (secret.client_id !== this.clientId) fail(502, 'revoke_failed', 'Cloudflare側の許可を取り消せませんでした。');
    for (const [token_type_hint, token] of [['refresh_token', secret.refresh_token], ['access_token', secret.access_token]]) {
      let response;
      try { response = await this.call(OAUTH + '/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token, token_type_hint, client_id: this.clientId, client_secret: this.clientSecret }) }); }
      catch { fail(502, 'revoke_failed', 'Cloudflare側の許可を取り消せませんでした。'); }
      if (response.status !== 200) fail(502, 'revoke_failed', 'Cloudflare側の許可を取り消せませんでした。');
    }
  }
}
