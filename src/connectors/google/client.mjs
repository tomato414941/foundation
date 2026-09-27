import { fail } from '../../errors.mjs';
import { GoogleOAuth, validGoogleToken } from '../google-oauth.mjs';

export const EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';
export const PROFILE_SCOPE = 'https://www.googleapis.com/auth/userinfo.profile';
// Foundation needs to know which Google account authorized, and nothing more; every other scope is the holder's
// choice (Gmail, Drive, Cloud Platform, ...).
export const GOOGLE_BASE_SCOPES = ['openid', EMAIL_SCOPE];
export const GOOGLE_SCOPE_DOCS = 'https://developers.google.com/identity/protocols/oauth2/scopes';
export const GOOGLE_API = 'https://www.googleapis.com';
export const GOOGLE_DOCS = 'https://developers.google.com/apis-explorer';
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

// One Google account, authorized for whatever scopes the holder allowed. The account is named by its address,
// which is also how the holder picks it on Google's screen.
export class GoogleClient extends GoogleOAuth {
  constructor(config = {}, options = {}) { super(config, options, { setting: 'Google', code: 'google_unavailable', name: 'Google' }); }
  authorize({ email, ...context }) { return super.authorize({ ...context, loginHint: email }); }
  grant(data, previous) { return super.grant(data, previous, scope => scope === 'email' ? EMAIL_SCOPE : scope === 'profile' ? PROFILE_SCOPE : scope); }
  async identity(accessToken) {
    const data = await this.request(USERINFO_URL, { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.sub !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(data.sub)
      || typeof data.email !== 'string' || data.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.email)
      || (data.email_verified !== undefined && typeof data.email_verified !== 'boolean')) this.invalidResponse();
    return { email: data.email.toLowerCase(), account_id: data.sub, email_verified: data.email_verified === true, checked_at: Date.now() };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (!validGoogleToken(data.access_token)) this.invalidResponse();
    const identity = await this.identity(data.access_token);
    if (previous && previous.subject !== identity.email) fail(409, 'account_changed', '接続し直すには同じGoogleアカウントを選んでください。');
    return { subject: identity.email, secret: { ...this.grant(data, previous?.secret), identity } };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.expires_at > Date.now() + 60_000) return existing;
    const next = this.grant(await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
    const identity = await this.identity(next.access_token);
    if (identity.email !== subject) fail(409, 'account_changed', 'Googleのアカウントが変わりました。接続を確認してください。');
    return { ...next, identity };
  }
  facts(secret) {
    return { label: secret.identity.email, account_id: secret.identity.account_id, email_verified: secret.identity.email_verified, scopes: secret.scopes };
  }
}
