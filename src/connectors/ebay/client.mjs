import { fail } from '../../errors.mjs';

export const EBAY_API = 'https://api.ebay.com';
export const EBAY_DOCS = 'https://developer.ebay.com/develop/guides/sell/authorization';
export const EBAY_SCOPES = ['https://api.ebay.com/oauth/api_scope/sell.account', 'https://api.ebay.com/oauth/api_scope/sell.inventory'];
const TOKEN_URL = EBAY_API + '/identity/v1/oauth2/token';
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[^\x21-\x7e]/.test(value);
const validText = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const userTokenType = value => typeof value === 'string' && ['user access token', 'bearer'].includes(value.toLowerCase());
const invalidResponse = () => fail(502, 'service_response', 'eBayからの認証応答を確認できませんでした。');
const reconnect = () => fail(409, 'reconnect_required', 'eBayの許可が失効しています。接続し直してください。');
const expiry = (seconds, now) => {
  const timestamp = now + seconds * 1000;
  if (!Number.isSafeInteger(seconds) || seconds <= 0 || !Number.isSafeInteger(timestamp) || timestamp > 8_640_000_000_000_000) invalidResponse();
  return timestamp;
};

// Production user OAuth. eBay identifies the registered callback by RuName, not by its URL.
// Token introspection supplies the stable account ID and actual scopes, independently of grants.
export class EbayClient {
  constructor({ clientId = '', clientSecret = '', ruName = '' } = {}, { fetcher = fetch } = {}) {
    const settings = [clientId, clientSecret, ruName];
    if (settings.some(Boolean) && !settings.every(value => typeof value === 'string' && value.trim())) throw new Error('Foundation eBay client ID, client secret and RuName are all required');
    this.enabled = settings.every(Boolean);
    this.clientId = clientId; this.clientSecret = clientSecret; this.ruName = ruName; this.fetcher = fetcher;
  }
  check() { if (!this.enabled) fail(503, 'ebay_unavailable', '現在eBayに接続できません。'); }
  authorize({ state }) {
    this.check();
    const url = new URL('https://auth.ebay.com/oauth2/authorize');
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: this.ruName, response_type: 'code',
      scope: EBAY_SCOPES.join(' '), state, prompt: 'login' }).toString();
    return url.href;
  }
  async call(path, values) {
    this.check();
    try {
      return await this.fetcher(TOKEN_URL + path, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64') },
      body: new URLSearchParams(values), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'service_unavailable', 'eBayに接続できませんでした。時間をおいて再度お試しください。'); }
  }
  async request(path, values) {
    const response = await this.call(path, values);
    let data;
    try { data = await response.json(); } catch {}
    if (!response.ok) {
      if (data?.error === 'invalid_grant' && values.grant_type === 'refresh_token') reconnect();
      if (data?.error === 'invalid_grant' && values.grant_type === 'authorization_code') fail(400, 'invalid_state', 'eBayの接続をやり直してください。');
      if (response.status === 429) fail(503, 'service_rate_limit', 'eBayの利用上限に達しました。時間をおいて再度お試しください。');
      // A failed client login is a server setting problem, not a revoked seller consent.
      if (response.status === 401 || data?.error === 'invalid_client') fail(503, 'ebay_unavailable', 'eBayの接続設定を確認できませんでした。');
      fail(502, 'service_unavailable', 'eBayで処理を完了できませんでした。');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    return data;
  }
  grant(data, previous) {
    if (!validToken(data.access_token) || !userTokenType(data.token_type)) invalidResponse();
    const now = Date.now(), expires_at = expiry(data.expires_in, now);
    const refresh_token = data.refresh_token === undefined ? previous?.refresh_token : data.refresh_token;
    if (refresh_token === undefined) fail(409, 'refresh_missing', '継続利用の許可を取得できませんでした。eBayに接続し直してください。');
    if (!validToken(refresh_token)) invalidResponse();
    const sameRefresh = previous && refresh_token === previous.refresh_token;
    const reportedExpiry = data.refresh_token_expires_in === undefined ? undefined : expiry(data.refresh_token_expires_in, now);
    if (!sameRefresh && reportedExpiry === undefined) invalidResponse();
    // An access-token refresh does not restart the original refresh token's lifetime.
    const refresh_expires_at = sameRefresh ? Math.min(previous.refresh_expires_at, reportedExpiry ?? Infinity) : reportedExpiry;
    if (!Number.isFinite(refresh_expires_at) || refresh_expires_at <= now) reconnect();
    return { client_id: this.clientId, access_token: data.access_token, refresh_token, expires_at, refresh_expires_at };
  }
  async inspect(secret, subject) {
    const data = await this.request('/introspect', { token: secret.access_token, token_type_hint: 'access_token' });
    if (data.active === false) reconnect();
    if (data.active !== true || data.client_id !== this.clientId || !validText(data.sub, 512) || /\s/.test(data.sub)
      || (data.username !== undefined && !validText(data.username, 254))
      || !userTokenType(data.token_type) || !Number.isSafeInteger(data.exp) || data.exp <= 0
      || typeof data.scope !== 'string' || data.scope.length > 8192 || /[^\x20-\x21\x23-\x5b\x5d-\x7e]/.test(data.scope)) invalidResponse();
    if (data.aud !== undefined && !(typeof data.aud === 'string' ? data.aud === EBAY_API
      : Array.isArray(data.aud) && data.aud.every(value => typeof value === 'string') && data.aud.includes(EBAY_API))) invalidResponse();
    if (data.iss !== undefined && data.iss !== EBAY_API + '/identity') invalidResponse();
    const expires_at = Math.min(secret.expires_at, expiry(data.exp, 0));
    if (expires_at <= Date.now()) reconnect();
    if (subject !== undefined && data.sub !== subject) fail(409, 'account_changed', '同じeBayアカウントで接続し直してください。');
    return { ...secret, expires_at, scopes: [...new Set(data.scope.split(' ').filter(Boolean))].sort(),
      identity: { subject: data.sub, username: data.username || '', checked_at: Date.now() } };
  }
  async exchange({ code }, previous) {
    const data = await this.request('', { grant_type: 'authorization_code', code, redirect_uri: this.ruName });
    const secret = await this.inspect(this.grant(data), previous?.subject);
    return { subject: secret.identity.subject, secret };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.client_id !== this.clientId) reconnect();
    if (existing.expires_at > Date.now() + 60_000) return this.inspect(existing, subject);
    if (existing.refresh_expires_at <= Date.now()) reconnect();
    // Omitting scope retains the permissions originally granted, including any differences.
    const data = await this.request('', { grant_type: 'refresh_token', refresh_token: existing.refresh_token });
    return this.inspect(this.grant(data, existing), subject);
  }
  facts(secret) {
    return { label: secret.identity.username || secret.identity.subject, account_id: secret.identity.subject, username: secret.identity.username,
      scopes: secret.scopes, missing_scopes: EBAY_SCOPES.filter(scope => !secret.scopes.includes(scope)),
      additional_scopes: secret.scopes.filter(scope => !EBAY_SCOPES.includes(scope)),
      refresh_expires_at: secret.refresh_expires_at, checked_at: secret.identity.checked_at };
  }
  async revoke(privateState) {
    this.check();
    if (privateState.client_id !== this.clientId) fail(502, 'revoke_failed', 'eBay側の許可を取り消せませんでした。');
    let response;
    try { response = await this.call('/revoke', { token: privateState.refresh_token, token_type_hint: 'refresh_token' }); }
    catch { fail(502, 'revoke_failed', 'eBay側の許可を取り消せませんでした。'); }
    // eBay returns an empty body on success, including for an already revoked token.
    if (response.status !== 200) fail(502, 'revoke_failed', 'eBay側の許可を取り消せませんでした。');
  }
}
