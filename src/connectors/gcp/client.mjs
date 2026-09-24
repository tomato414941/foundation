import { fail } from '../../errors.mjs';
import { GoogleOAuth, validGoogleToken } from '../google-oauth.mjs';

export const GCP_API = 'https://cloudresourcemanager.googleapis.com';
export const GCP_DOCS = 'https://docs.cloud.google.com/apis/docs/overview';
export const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';
export const GCP_SCOPES = ['openid', EMAIL_SCOPE, CLOUD_PLATFORM_SCOPE].sort();
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

export class GcpClient extends GoogleOAuth {
  constructor(config = {}, options = {}) { super(config, options, { setting: 'GCP', code: 'gcp_unavailable', name: 'Google Cloud' }); }
  authorize({ email, ...context }) { return super.authorize({ ...context, scopes: GCP_SCOPES, loginHint: email }); }
  grant(data, previous) { return super.grant(data, previous, scope => scope === 'email' ? EMAIL_SCOPE : scope); }
  async identity(accessToken) {
    const data = await this.request(USERINFO_URL, { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.sub !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(data.sub)
      || (data.email !== undefined && (typeof data.email !== 'string' || data.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.email)))
      || (data.email_verified !== undefined && typeof data.email_verified !== 'boolean')) this.invalidResponse();
    // Email is display metadata; the stable Google ID pins the account.
    return { subject: data.sub, email: data.email?.toLowerCase() || '', email_verified: data.email_verified === true, checked_at: Date.now() };
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (!validGoogleToken(data.access_token)) this.invalidResponse();
    const identity = await this.identity(data.access_token);
    if (previous && previous.subject !== identity.subject) fail(409, 'account_changed', '接続し直すには同じGoogleアカウントを選んでください。');
    return { subject: identity.subject, secret: { ...this.grant(data, previous?.secret), identity } };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.expires_at > Date.now() + 60_000) return existing;
    const next = this.grant(await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
    const identity = await this.identity(next.access_token);
    if (identity.subject !== subject) fail(409, 'account_changed', 'Google Cloudのアカウントが変わりました。接続を確認してください。');
    return { ...next, identity };
  }
  facts(secret) {
    return { label: secret.identity.email || secret.identity.subject, account_id: secret.identity.subject, email_verified: secret.identity.email_verified, scopes: secret.scopes,
      missing_scopes: GCP_SCOPES.filter(scope => !secret.scopes.includes(scope)),
      additional_scopes: secret.scopes.filter(scope => !GCP_SCOPES.includes(scope)),
      iam_checked: false, checked_at: secret.identity.checked_at };
  }
}
