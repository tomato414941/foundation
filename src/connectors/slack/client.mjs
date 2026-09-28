import { fail } from '../../errors.mjs';

export const SLACK_API = 'https://slack.com/api';
export const SLACK_DOCS = 'https://api.slack.com/methods';
export const SLACK_SCOPE_DOCS = 'https://api.slack.com/scopes';
export const SLACK_SETTINGS = 'https://api.slack.com/apps';
// Slack says who installed with auth.test, which needs no scope; every bot scope is the holder's choice.
export const SLACK_BASE_SCOPES = [];
const validToken = value => typeof value === 'string' && value.length > 0 && value.length <= 8192 && !/[^\x21-\x7e]/.test(value);
const invalidResponse = () => fail(502, 'service_response', 'Slackからの応答を確認できませんでした。');
const reconnect = () => fail(409, 'reconnect_required', 'Slackの許可が失効しています。接続し直してください。');

// A Slack app installed to one workspace: a bot token for that workspace, with the bot scopes the holder allowed.
// Slack departs from plain OAuth 2.0 where a connector must know it: scopes are separated by commas, success is said
// by "ok" in the body rather than by the status, and a token may rotate (when the app turns that on) or not.
export class SlackClient {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error('Both Foundation Slack client ID and client secret are required');
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId; this.clientSecret = clientSecret; this.fetcher = fetcher;
  }
  check() { if (!this.enabled) fail(503, 'slack_unavailable', '現在Slackに接続できません。自分のSlackアプリを選んでください。'); }
  authorize({ state, redirectUri, scopes }) {
    this.check();
    const url = new URL('https://slack.com/oauth/v2/authorize');
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: redirectUri, state, scope: scopes.join(',') }).toString();
    return url.href;
  }
  // A Web API method: form-encoded, answered with { ok, ... }.
  async call(method, values, token) {
    let response;
    try {
      response = await this.fetcher(SLACK_API + '/' + method, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(12_000),
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: new URLSearchParams(values) });
    } catch { fail(502, 'service_unavailable', 'Slackに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 429) fail(503, 'service_rate_limit', 'Slackの利用上限に達しました。時間をおいて再度お試しください。');
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    if (!data || typeof data !== 'object' || typeof data.ok !== 'boolean') invalidResponse();
    return data;
  }
  grant(data, previous) {
    if (!data.ok) {
      if (['invalid_refresh_token', 'invalid_grant_type', 'token_revoked', 'token_expired', 'account_inactive'].includes(data.error)) reconnect();
      if (['invalid_code', 'code_already_used', 'bad_redirect_uri'].includes(data.error)) fail(400, 'invalid_state', 'Slackの接続をやり直してください。');
      if (['invalid_client_id', 'bad_client_secret'].includes(data.error)) fail(400, 'invalid_app', 'Slackがアプリのクライアント IDかシークレットを受け付けませんでした。');
      fail(502, 'service_unavailable', 'Slackで処理を完了できませんでした。');
    }
    if (!validToken(data.access_token) || (data.scope !== undefined && typeof data.scope !== 'string')) invalidResponse();
    const expiresIn = data.expires_in === undefined ? null : Number(data.expires_in);
    if (expiresIn !== null && !(Number.isSafeInteger(expiresIn) && expiresIn > 0)) invalidResponse();
    const refresh = data.refresh_token ?? previous?.refresh_token ?? null;
    if (refresh !== null && !validToken(refresh)) invalidResponse();
    const scopes = typeof data.scope === 'string' ? [...new Set(data.scope.split(',').map(scope => scope.trim()).filter(Boolean))].sort() : previous?.scopes ?? [];
    return { access_token: data.access_token, refresh_token: refresh, expires_at: expiresIn === null ? null : Date.now() + expiresIn * 1000, scopes, client_id: this.clientId };
  }
  // Which workspace, and which bot there: what auth.test says of the token.
  async identity(token) {
    const data = await this.call('auth.test', {}, token);
    if (!data.ok) { if (['invalid_auth', 'token_revoked', 'account_inactive', 'not_authed'].includes(data.error)) reconnect(); invalidResponse(); }
    const text = (value, max = 255) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x1f]/.test(value);
    if (!text(data.team_id, 64) || !text(data.team ?? 'x') || (data.bot_id !== undefined && !text(data.bot_id, 64))) invalidResponse();
    return { team_id: data.team_id, team: data.team || data.team_id, url: typeof data.url === 'string' ? data.url : '', bot_id: data.bot_id ?? null, checked_at: Date.now() };
  }
  async exchange({ code, redirectUri }, previous) {
    this.check();
    const grant = this.grant(await this.call('oauth.v2.access', { client_id: this.clientId, client_secret: this.clientSecret, code, redirect_uri: redirectUri }));
    const identity = await this.identity(grant.access_token);
    const subject = 'team:' + identity.team_id;
    if (previous && previous.subject !== subject) fail(409, 'account_changed', '接続し直すには同じワークスペースを選んでください。');
    return { subject, secret: { ...grant, identity } };
  }
  // A token that does not rotate lasts until it is revoked; one that rotates is renewed before it runs out.
  async token(existing, { subject }) {
    this.check();
    if (existing.client_id !== this.clientId) reconnect();
    if (existing.expires_at === null || existing.expires_at > Date.now() + 60_000) return existing;
    if (!existing.refresh_token) reconnect();
    const next = this.grant(await this.call('oauth.v2.access', { client_id: this.clientId, client_secret: this.clientSecret, grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
    const identity = await this.identity(next.access_token);
    if ('team:' + identity.team_id !== subject) fail(409, 'account_changed', 'Slackのワークスペースが変わりました。接続し直してください。');
    return { ...next, identity };
  }
  async revoke(secret) {
    const data = await this.call('auth.revoke', {}, secret.access_token);
    if (!data.ok && !['invalid_auth', 'token_revoked', 'not_authed'].includes(data.error)) fail(502, 'revoke_failed', 'Slackの許可を取り消せませんでした。');
  }
  facts(secret) {
    return { label: secret.identity.team, team_id: secret.identity.team_id, workspace_url: secret.identity.url, bot_id: secret.identity.bot_id,
      client_id: secret.client_id, scopes: secret.scopes, rotating: secret.expires_at !== null, checked_at: secret.identity.checked_at };
  }
}
