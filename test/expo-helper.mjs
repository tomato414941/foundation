import { createHash } from 'node:crypto';
import { ExpoClient, EXPO_API } from '../src/services/expo.mjs';
import { expoToken, expoLogin, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export class FakeExpo extends ExpoClient {
  constructor({ sessionLogin = false } = {}) {
    super({ fetcher: (url, options) => this.fetch(url, options), sessionLogin });
    this.calls = [];
    this.actor = { __typename: 'User', id: 'expo-user-1', username: 'fixture-expo-user' };
  }
  tokenValue(label = 'personal') { return createHash('sha256').update('expo-fixture:' + label).digest('hex'); }
  async fetch(url, options) {
    this.calls.push({ url, options });
    const body = JSON.parse(options.body);
    if (url !== EXPO_API || options.method !== 'POST' || !body.query.startsWith('query FoundationIdentity ') || /mutation|build|accessTokens/.test(body.query)) throw new Error('Only Expo identity reads are allowed in this fixture');
    if (this.identityHandler) return this.identityHandler(url, options);
    if (![this.tokenValue(), this.tokenValue('second')].includes(options.headers.authorization?.slice(7))) return json({ errors: [{ message: 'fixture secret upstream error', extensions: { code: 'UNAUTHENTICATED' } }] });
    return json({ data: { meActor: this.actor } });
  }
}

export async function expoFixture(t, options = {}) {
  const expo = options.expo || new FakeExpo(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, adapters: [expoToken(expo), ...(expo.sessionLoginEnabled ? [expoLogin(expo)] : []), gmailReadonly(gmail), gmailMetadata(gmail)], ...options });
  const importExpo = ({ token = expo.tokenValue(), ...extra } = {}, requestOptions = {}) => f.request('/api/adapters/expo.token/connect', { method: 'POST', data: { name: 'Expo', values: { token }, ...extra }, ...requestOptions });
  async function expoAccount(extra = {}) {
    const result = await importExpo(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.credentials.find(account => account.id === result.json.credential_id);
  }
  return { ...f, expo, importExpo, expoAccount };
}
