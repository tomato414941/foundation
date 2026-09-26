import { createClient } from '@supabase/supabase-js';
import { fail } from './errors.mjs';

export class SupabaseAuth {
  constructor({ url = '', key = '', emailEnabled = true, fetcher = fetch } = {}) {
    this.enabled = Boolean(url && key);
    this.emailEnabled = this.enabled && emailEnabled;
    if (Boolean(url) !== Boolean(key)) throw new Error('Both Foundation Supabase URL and publishable key are required');
    if (!this.enabled) return;
    const target = new URL(url);
    if ((target.protocol !== 'https:' && !(target.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(target.hostname))) || target.username || target.password || target.search || target.hash || target.pathname !== '/') throw new Error('Invalid Foundation Supabase URL');
    let role;
    try { role = JSON.parse(Buffer.from(key.split('.')[1], 'base64url')).role; } catch {}
    if (key.startsWith('sb_secret_') || role === 'service_role') throw new Error('Use a Supabase publishable/anon key, not a privileged key');
    this.client = () => createClient(target.origin, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      global: { fetch: (input, init) => fetcher(input, { ...init, redirect: 'error', signal: AbortSignal.timeout(12_000) }) },
    });
  }
  check() { if (!this.enabled) fail(503, 'auth_unavailable', '現在ログインを利用できません。'); }
  error(error) {
    if (error?.status === 429) fail(429, 'login_rate_limit', 'しばらく待ってからお試しください。');
    if (error?.status >= 500 || !error?.status) fail(503, 'auth_unavailable', 'ログインサービスに接続できません。しばらく待ってからお試しください。');
    fail(401, 'login_required', 'もう一度ログインしてください。');
  }
  session(data) {
    const value = data?.session;
    if (!value?.access_token || !value.refresh_token || !Number.isFinite(value.expires_at) || !value.user?.id || !value.user.email || value.user.is_anonymous) fail(401, 'login_required', 'ログインを完了できませんでした。');
    return { access_token: value.access_token, refresh_token: value.refresh_token, expires_at: value.expires_at * 1000, user: { id: value.user.id, email: value.user.email } };
  }
  async sendLink(email, redirectUri) {
    this.check();
    if (!this.emailEnabled) fail(503, 'email_unavailable', '現在ログインを利用できません。');
    const { error } = await this.client().auth.signInWithOtp({ email, options: { shouldCreateUser: true, emailRedirectTo: redirectUri } });
    if (error?.status === 429) fail(429, 'email_rate_limit', 'メール送信の上限に達しました。時間をおいてお試しください。');
    if (error?.code === 'email_address_not_authorized') fail(503, 'email_unavailable', 'このメールアドレスにはログイン用のメールを送信できません。');
    if (error) fail(503, 'email_unavailable', 'メールを送信できませんでした。時間をおいてお試しください。');
  }
  async verifyLink(tokenHash) {
    this.check();
    const { data, error } = await this.client().auth.verifyOtp({ token_hash: tokenHash, type: 'email' });
    if (error?.status === 429) fail(429, 'login_rate_limit', 'しばらく待ってからお試しください。');
    if (error?.status >= 500 || (error && !error.status)) this.error(error);
    if (error) fail(401, 'invalid_link', 'リンクが無効か、有効期限が切れています。');
    return this.session(data);
  }
  async refresh(refreshToken) {
    this.check();
    const { data, error } = await this.client().auth.refreshSession({ refresh_token: refreshToken });
    if (error) this.error(error);
    return this.session(data);
  }
  async user(accessToken) {
    this.check();
    const { data, error } = await this.client().auth.getUser(accessToken);
    if (error) this.error(error);
    if (!data.user?.id || !data.user.email || data.user.is_anonymous) fail(401, 'login_required', 'もう一度ログインしてください。');
    return { id: data.user.id, email: data.user.email };
  }
  async logout(accessToken) {
    this.check();
    // This SDK method uses the user's JWT, not a privileged key. Do not sign out other devices.
    const { error } = await this.client().auth.admin.signOut(accessToken, 'local');
    if (error && ![401, 403, 404].includes(error.status)) this.error(error);
  }
}
