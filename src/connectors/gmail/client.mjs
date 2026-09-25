import { fail } from '../../errors.mjs';
import { GoogleOAuth, validGoogleToken } from '../google-oauth.mjs';

export const METADATA_SCOPE = 'https://www.googleapis.com/auth/gmail.metadata';
export const READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
export const SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
export const GMAIL_API = 'https://gmail.googleapis.com/gmail/v1';
export const GMAIL_DOCS = 'https://developers.google.com/workspace/gmail/api/reference/rest';
const IDENTITY_SCOPES = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'];

export class GmailClient extends GoogleOAuth {
  constructor(config = {}, options = {}) { super(config, options, { setting: 'Google', code: 'gmail_unavailable', name: 'Gmail' }); }
  scopes(range) {
    if (range === 'readonly') return [READONLY_SCOPE];
    if (range === 'metadata') return [METADATA_SCOPE];
    if (range === 'read-send') return [READONLY_SCOPE, SEND_SCOPE];
    throw new Error('Unknown Gmail range: ' + range);
  }
  authorize({ range, email, ...context }) { return super.authorize({ ...context, scopes: this.scopes(range), loginHint: email }); }
  async identity(accessToken) {
    const data = await this.request(GMAIL_API + '/users/me/profile?fields=emailAddress', { headers: { authorization: 'Bearer ' + accessToken } });
    if (typeof data.emailAddress !== 'string' || data.emailAddress.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(data.emailAddress)) fail(502, 'service_response', 'Gmailのアドレスを確認できませんでした。');
    return data.emailAddress.toLowerCase();
  }
  async exchange({ code, verifier, redirectUri }, previous) {
    const data = await this.tokenRequest({ code, code_verifier: verifier, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    if (!validGoogleToken(data.access_token)) this.invalidResponse();
    // Identity must match before reusing a previous refresh token.
    const subject = await this.identity(data.access_token);
    if (previous && previous.subject !== subject) fail(409, 'account_changed', '登録し直すには同じGoogleアカウントを選んでください。');
    return { subject, secret: this.grant(data, previous?.secret) };
  }
  async token(existing, { subject }) {
    this.check();
    if (existing.expires_at > Date.now() + 60_000) return existing;
    const next = this.grant(await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: existing.refresh_token }), existing);
    if (await this.identity(next.access_token) !== subject) fail(409, 'account_changed', 'Gmailのアカウントが変わりました。登録を確認してください。');
    return next;
  }
  facts(secret, subject, range) {
    const requested = this.scopes(range);
    const expected = new Set([...IDENTITY_SCOPES, METADATA_SCOPE, ...requested]);
    return { label: subject, scopes: secret.scopes,
      missing_scopes: requested.filter(scope => !secret.scopes.includes(scope)),
      additional_scopes: secret.scopes.filter(scope => !expected.has(scope)) };
  }
}
