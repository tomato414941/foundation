import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const GITHUB_API = 'https://api.github.com';
export const GITHUB_DOCS = 'https://docs.github.com/rest';
export const GITHUB_SETTINGS = 'https://github.com/settings/applications';
// What `gh auth login` asks for, and workflow so that pushes touching Actions are not refused.
export const GITHUB_SCOPES = ['gist', 'read:org', 'repo', 'workflow'];
const hash = value => createHash('sha256').update(value).digest('hex');
const invalidResponse = () => fail(502, 'service_response', 'GitHubからの応答を確認できませんでした。');

// An OAuth App: the owner authorizes once and Foundation keeps a token that does not expire.
// It reaches what the owner reaches, within the scopes above. Disconnecting revokes the grant at GitHub.
export class GitHubClient {
  constructor({ clientId = '', clientSecret = '' } = {}, { fetcher = fetch } = {}) {
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error('Both Foundation GitHub client ID and client secret are required');
    this.enabled = Boolean(clientId && clientSecret);
    this.clientId = clientId; this.clientSecret = clientSecret; this.fetcher = fetcher;
  }
  check() { if (!this.enabled) fail(503, 'github_unavailable', '現在GitHubに接続できません。'); }
  authorize({ state, verifier, redirectUri }) {
    this.check();
    const url = new URL('https://github.com/login/oauth/authorize');
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: redirectUri, scope: GITHUB_SCOPES.join(' '), state, allow_signup: 'false',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
    return url.href;
  }
  async call(url, options = {}) {
    let response;
    try { response = await this.fetcher(url, { ...options, headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'Foundation', ...options.headers }, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'GitHubに接続できませんでした。時間をおいて再度お試しください。'); }
    return response;
  }
  async json(response) {
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) invalidResponse();
    return data;
  }
  // Who the token belongs to and which scopes it carries, as GitHub reports them.
  async inspect(token) {
    const response = await this.call(GITHUB_API + '/user', { headers: { authorization: 'Bearer ' + token } });
    if (response.status === 401) fail(409, 'reconnect_required', 'GitHubの許可が取り消されたか、無効になっています。登録し直してください。');
    if (response.status === 403 || response.status === 429) fail(503, 'service_rate_limit', 'GitHubの利用上限に達しました。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'service_unavailable', 'GitHubで処理を完了できませんでした。');
    const user = await this.json(response);
    if (!Number.isSafeInteger(user.id) || typeof user.login !== 'string' || !/^[A-Za-z0-9-]{1,39}$/.test(user.login)) invalidResponse();
    const scopes = String(response.headers.get('x-oauth-scopes') || '').split(',').map(scope => scope.trim()).filter(Boolean).sort();
    return { id: user.id, login: user.login, scopes };
  }
  secret(token, identity) {
    return { access_token: token, credential_type: 'oauth2_access_token', expires_at: null, expiry_known: true, scopes: identity.scopes,
      details: { login: identity.login, user_id: identity.id, token_hash: hash(token), checked_at: Date.now() } };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    this.check();
    const response = await this.call('https://github.com/login/oauth/access_token', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: this.clientId, client_secret: this.clientSecret, code, redirect_uri: redirectUri, code_verifier: verifier }) });
    if (!response.ok) fail(502, 'service_unavailable', 'GitHubで処理を完了できませんでした。');
    const data = await this.json(response);
    if (data.error) fail(400, 'invalid_state', '接続をやり直してください。');
    if (typeof data.access_token !== 'string' || !data.access_token || data.access_token.length > 512) invalidResponse();
    const identity = await this.inspect(data.access_token);
    // The owner may not narrow an OAuth App's scopes, but an organization policy or a stale grant can leave one out.
    if (!identity.scopes.includes('repo')) fail(409, 'scope_mismatch', 'GitHubでリポジトリへのアクセスが許可されませんでした。');
    const subject = 'user:' + identity.id;
    if (previous && previous.subject !== subject) fail(409, 'account_changed', '登録し直すには同じGitHubアカウントを選んでください。');
    return { subject, secret: this.secret(data.access_token, identity) };
  }
  // The token does not expire; each use asks GitHub whether it still works and for whom.
  async token(store, credential) {
    this.check();
    if (credential.status !== 'connected') fail(409, 'reconnect_required', 'GitHubの許可が取り消されたか、無効になっています。登録し直してください。');
    const existing = store.secret(credential);
    try {
      const identity = await this.inspect(existing.access_token);
      if ('user:' + identity.id !== credential.subject) fail(409, 'account_changed', 'GitHubのアカウントが変わりました。登録を確認してください。');
      const next = this.secret(existing.access_token, identity);
      store.saveSecret(credential, { ...next, ...(existing.verification ? { verification: existing.verification } : {}) });
      return next;
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed'].includes(error.code)) store.reconnectRequired(credential);
      throw error;
    }
  }
  facts(secret) {
    return { label: secret.details.login, credential_type: 'oauth2_access_token', expires_at: null, expiry_known: true, management_url: GITHUB_SETTINGS + '/' + this.clientId, scopes: secret.scopes };
  }
  // Deleting the grant revokes every token this app holds for the owner.
  async revoke(secret) {
    this.check();
    const response = await this.call(GITHUB_API + '/applications/' + this.clientId + '/grant', { method: 'DELETE',
      headers: { authorization: 'Basic ' + Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'), 'content-type': 'application/json' }, body: JSON.stringify({ access_token: secret.access_token }) });
    if (!response.ok && response.status !== 404 && response.status !== 422) fail(502, 'revoke_failed', 'GitHubの許可を取り消せませんでした。この認証情報の受け渡しは停止しています。もう一度お試しください。');
  }
}
