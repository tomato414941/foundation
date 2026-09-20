import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const EXPO_API = 'https://api.expo.dev/graphql';
export const EXPO_DOCS = 'https://docs.expo.dev/accounts/programmatic-access/';
export const EXPO_TOKENS = 'https://expo.dev/settings/access-tokens';
export const EXPO_SCOPE = 'expo:access-token';
export const EXPO_SESSION_SCOPE = 'expo:session';
const digest = token => createHash('sha256').update(token).digest('hex');
const identityQuery = 'query FoundationIdentity { meActor { __typename id ... on UserActor { username } ... on Robot { firstName } } }';
const invalidResponse = () => fail(502, 'provider_response', 'Expoからの応答を確認できませんでした。');

// EAS login returns a session, not an EXPO_TOKEN. Keep the two credential
// types separate; passwords and OTPs never become stored credentials.
export class ExpoProvider {
  constructor({ fetcher = fetch, sessionLogin = false } = {}) { this.enabled = true; this.fetcher = fetcher; this.sessionLoginEnabled = sessionLogin; }
  check() { if (!this.enabled) fail(503, 'expo_unavailable', '現在Expoに接続できません。'); }
  async inspect(token, { session = false } = {}) {
    const reconnectMessage = session ? 'Expoのログインが無効になっています。もう一度接続してください。' : 'トークンが無効か、利用できません。Expoのトークン管理画面で確認してください。';
    if (typeof token !== 'string' || !(session ? /^[\x20-\x7e]{20,8192}$/ : /^[A-Za-z0-9._~-]{20,1024}$/).test(token)) fail(400, 'invalid_credential', 'Expoの認証情報を確認できませんでした。');
    let response;
    try {
      response = await this.fetcher(EXPO_API, { method: 'POST', headers: { ...(session ? { 'expo-session': token } : { authorization: 'Bearer ' + token }), 'content-type': 'application/json' },
        body: JSON.stringify({ query: identityQuery }), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'provider_unavailable', 'Expoに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 401 || response.status === 403) fail(409, 'reconnect_required', reconnectMessage);
    if (response.status === 429) fail(503, 'provider_rate_limit', 'Expoへの確認が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'provider_unavailable', 'Expoで処理を完了できませんでした。');
    let result;
    try { result = await response.json(); } catch { invalidResponse(); }
    if (!result || typeof result !== 'object' || Array.isArray(result)) invalidResponse();
    if (result.errors !== undefined && !Array.isArray(result.errors)) invalidResponse();
    if (result.errors?.length) {
      if (result.errors.some(error => ['UNAUTHENTICATED', 'FORBIDDEN'].includes(error?.extensions?.code))) fail(409, 'reconnect_required', reconnectMessage);
      invalidResponse();
    }
    const actor = result.data?.meActor;
    if (actor === null) fail(409, 'reconnect_required', reconnectMessage);
    if (!actor || typeof actor.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(actor.id) || !['User', 'SSOUser', 'Robot'].includes(actor.__typename)) invalidResponse();
    const label = actor.__typename === 'Robot' ? actor.firstName : actor.username;
    if (typeof label !== 'string' || !label.trim() || label.length > 256 || /[\x00-\x1f\x7f]/.test(label)) invalidResponse();
    if (session && actor.__typename === 'Robot') invalidResponse();
    return { access_token: token, credential_type: session ? 'expo_session' : 'api_key', expires_at: null, expiry_known: false, scopes: [session ? EXPO_SESSION_SCOPE : EXPO_SCOPE],
      details: { token_hash: digest(token), actor_id: actor.id, label, actor_type: actor.__typename, checked_at: Date.now() } };
  }
  async login({ username, password, otp }) {
    this.check();
    if (!this.sessionLoginEnabled) fail(503, 'login_unavailable', '現在この方法ではExpoに接続できません。');
    if (typeof username !== 'string' || !username.trim() || username.length > 254 || /[\s\x00-\x1f]/.test(username)) fail(400, 'invalid_login', 'Expoのメールアドレスまたはユーザー名を入力してください。');
    if (typeof password !== 'string' || !password || password.length > 1024 || /[\x00\r\n]/.test(password)) fail(400, 'invalid_login', 'Expoのパスワードを入力してください。');
    if (otp !== undefined && (typeof otp !== 'string' || !/^[A-Za-z0-9 -]{4,64}$/.test(otp))) fail(400, 'invalid_otp', '認証コードを確認してください。');
    let response, result;
    try {
      response = await this.fetcher('https://api.expo.dev/v2/auth/loginAsync', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password, ...(otp === undefined ? {} : { otp }) }), redirect: 'error', signal: AbortSignal.timeout(12_000) });
    } catch { fail(502, 'provider_unavailable', 'Expoに接続できませんでした。時間をおいて再度お試しください。'); }
    finally { password = ''; otp = undefined; }
    if (response.status === 429) fail(503, 'provider_rate_limit', 'ログインの試行が続いています。時間をおいて再度お試しください。');
    if (response.status >= 500) fail(502, 'provider_unavailable', 'Expoで処理を完了できませんでした。');
    try { result = await response.json(); } catch { invalidResponse(); }
    if (!result || typeof result !== 'object' || Array.isArray(result) || (result.errors !== undefined && !Array.isArray(result.errors))) invalidResponse();
    const errors = Array.isArray(result?.errors) ? result.errors : [];
    if (errors.some(error => error?.code === 'ONE_TIME_PASSWORD_REQUIRED')) return { challenge: { type: 'otp', delivery: errors.some(error => error?.metadata?.smsAutomaticallySent === true) ? 'sms' : 'authenticator' } };
    if (!response.ok || errors.length) {
      if ([400, 401, 403].includes(response.status) || errors.length) fail(400, 'expo_login_failed', 'Expoにログインできませんでした。入力内容を確認してください。');
      fail(502, 'provider_unavailable', 'Expoで処理を完了できませんでした。');
    }
    const sessionSecret = result?.data?.sessionSecret;
    if (typeof sessionSecret !== 'string' || !/^[\x20-\x7e]{20,8192}$/.test(sessionSecret)) invalidResponse();
    try {
      const credentials = await this.inspect(sessionSecret, { session: true });
      return { email: 'session:' + credentials.details.token_hash, credentials };
    } catch (error) {
      await this.revoke({ credential_type: 'expo_session', access_token: sessionSecret }).catch(() => {});
      throw error;
    }
  }
  async importToken({ token, mode }) {
    this.check();
    if (mode !== 'access-token') fail(400, 'invalid_scope', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token);
    return { email: 'token:' + credentials.details.token_hash, credentials };
  }
  async token(store, account) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'Expoへの接続を確認し、新しい接続を追加してください。');
    try {
      const previous = store.secrets(account), session = previous.credential_type === 'expo_session';
      if (session && !this.sessionLoginEnabled) fail(409, 'reconnect_required', 'Expoのログイン接続は現在利用できません。アクセストークンで新しい接続を追加してください。');
      const next = await this.inspect(previous.access_token, { session });
      if (account.email !== (session ? 'session:' : 'token:') + next.details.token_hash || previous.details.actor_id !== next.details.actor_id) invalidResponse();
      store.saveCredentials(account, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    const session = credentials.credential_type === 'expo_session';
    return { label: credentials.details.label + (credentials.details.actor_type === 'Robot' ? ' (Robot)' : ''), credential_type: session ? 'expo_session' : 'api_key', can_revoke: session,
      expires_at: null, expiry_known: false, ...(session ? {} : { management_url: EXPO_TOKENS }) };
  }
  canRevoke(credentials) { return credentials.credential_type === 'expo_session'; }
  async revoke(credentials) {
    if (!this.canRevoke(credentials)) fail(409, 'manual_revocation_required', 'トークンの無効化はExpoのトークン管理画面で行ってください。');
    let response;
    try { response = await this.fetcher('https://api.expo.dev/v2/auth/logout', { method: 'POST', headers: { 'content-type': 'application/json', 'expo-session': credentials.access_token }, body: '{}', redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'provider_unavailable', 'Expo側のログアウトを確認できませんでした。もう一度お試しください。'); }
    if (!response.ok && ![401, 403].includes(response.status)) fail(502, 'provider_unavailable', 'Expo側のログアウトを確認できませんでした。もう一度お試しください。');
  }
}
