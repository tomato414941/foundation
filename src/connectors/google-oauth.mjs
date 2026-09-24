import { createHash } from 'node:crypto';
import { fail } from '../errors.mjs';

export const validGoogleToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[\x00-\x20\x7f]/.test(value);

// Google transport and token format only. Each connector owns scopes, identity and outputs.
export class GoogleOAuth {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}, { setting, code, name }) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error(`Both Foundation ${setting} client ID and client secret are required`);
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId; this.clientSecret = clientSecret; this.fetcher = fetcher;
    this.unavailableCode = code; this.name = name;
  }
  check() { if (!this.enabled) fail(503, this.unavailableCode, `現在${this.name}に接続できません。`); }
  authorize({ state, verifier, redirectUri, scopes, loginHint }) {
    this.check();
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: this.clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: scopes.join(' '), access_type: 'offline', prompt: 'consent select_account',
      include_granted_scopes: 'false', state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
      ...(loginHint ? { login_hint: loginHint } : {}),
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
      if (data?.error === 'invalid_grant' || response.status === 401) fail(409, 'reconnect_required', `${this.name}に接続し直してください。`);
      if (response.status === 429) fail(503, 'service_rate_limit', 'Googleの利用上限に達しました。時間をおいて再度お試しください。');
      fail(502, 'service_unavailable', 'Googleで処理を完了できませんでした。');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) this.invalidResponse();
    return data;
  }
  invalidResponse() { fail(502, 'service_response', `${this.name}の認証応答を確認できませんでした。`); }
  tokenRequest(values) {
    this.check();
    return this.request('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, ...values }) });
  }
  grant(data, previous, normalizeScope = scope => scope) {
    if (!validGoogleToken(data.access_token) || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 86400
      || (data.token_type !== undefined && (typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer'))) this.invalidResponse();
    let scopes;
    if (data.scope === undefined && previous) scopes = previous.scopes;
    else {
      if (typeof data.scope !== 'string' || !data.scope.trim() || data.scope.length > 8192 || /[^\x20-\x21\x23-\x5b\x5d-\x7e]/.test(data.scope)) this.invalidResponse();
      scopes = [...new Set(data.scope.trim().split(/ +/).map(normalizeScope))].sort();
    }
    const refreshToken = data.refresh_token === undefined ? previous?.refresh_token : data.refresh_token;
    if (!refreshToken) fail(409, 'refresh_missing', `継続利用の許可を取得できませんでした。${this.name}に接続し直してください。`);
    if (!validGoogleToken(refreshToken)) this.invalidResponse();
    return { access_token: data.access_token, refresh_token: refreshToken, scopes, expires_at: Date.now() + data.expires_in * 1000 };
  }
  async revoke(privateState) {
    this.check();
    let response;
    try { response = await this.call('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: privateState.refresh_token }) }); }
    catch { fail(502, 'revoke_failed', 'Google側の許可を取り消せませんでした。'); }
    if (!response.ok) {
      let data; try { data = await response.json(); } catch {}
      if (!(response.status === 400 && data?.error === 'invalid_token')) fail(502, 'revoke_failed', 'Google側の許可を取り消せませんでした。');
    }
  }
}
