import { randomUUID } from 'node:crypto';
import { FakeExpo, expoFixture } from './expo-helper.mjs';
import { EXPO_API } from '../src/services/expo.mjs';
import { json } from './helpers.mjs';

export const LOGIN_PASSWORD = 'fixture-password-do-not-use';
export const LOGIN_OTP = '123456';
export class FakeExpoLogin extends FakeExpo {
  constructor() { super({ sessionLogin: true }); this.sessions = new Map(); }
  async fetch(url, options) {
    if (url === 'https://api.expo.dev/v2/auth/loginAsync') {
      this.calls.push({ url, options });
      if (this.loginHandler) { const result = await this.loginHandler(url, options); if (result) return result; }
      const input = JSON.parse(options.body);
      if (input.password !== LOGIN_PASSWORD) return json({ errors: [{ code: 'INVALID_CREDENTIALS', message: 'secret ' + input.password }] }, 401);
      if (/^(otp|sms)-/.test(input.username) && !input.otp) return json({ errors: [{ code: 'ONE_TIME_PASSWORD_REQUIRED', metadata: { smsAutomaticallySent: input.username.startsWith('sms-'), password: LOGIN_PASSWORD } }] }, 400);
      if (input.otp && input.otp !== LOGIN_OTP) return json({ errors: [{ code: 'ONE_TIME_PASSWORD_INCORRECT', message: 'secret ' + input.otp }] }, 400);
      const secret = 'fixture-session-' + randomUUID();
      this.sessions.set(secret, { __typename: 'User', id: 'expo-' + input.username.replace(/[^A-Za-z0-9_-]/g, '-'), username: input.username });
      return json({ data: { sessionSecret: secret } });
    }
    if (url === 'https://api.expo.dev/v2/auth/logout') {
      this.calls.push({ url, options });
      if (this.logoutHandler) return this.logoutHandler(url, options);
      this.sessions.delete(options.headers['expo-session']);
      return json({ data: {} });
    }
    if (url === EXPO_API && options.headers['expo-session']) {
      this.calls.push({ url, options });
      if (this.identityHandler) return this.identityHandler(url, options);
      if (!JSON.parse(options.body).query.startsWith('query FoundationIdentity ')) throw new Error('Only identity reads are allowed');
      const actor = this.sessions.get(options.headers['expo-session']);
      return actor ? json({ data: { meActor: actor } }) : json({ errors: [{ extensions: { code: 'UNAUTHENTICATED' } }] });
    }
    return super.fetch(url, options);
  }
}
export async function expoLoginFixture(t, options = {}) {
  const expo = options.expo || new FakeExpoLogin();
  const f = await expoFixture(t, { ...options, expo });
  const loginExpo = (input = {}, requestOptions = {}) => f.request('/api/adapters/expo.login/connect', { method: 'POST', data: { name: 'Expo', permission: 'session', username: 'fixture-user', password: LOGIN_PASSWORD, ...input }, ...requestOptions });
  return { ...f, loginExpo };
}
