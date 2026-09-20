import { createHash } from 'node:crypto';
import { ExpoProvider, EXPO_API } from '../src/providers/expo.mjs';
import { expoConnection, gmailConnection } from '../src/providers/catalog.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export class FakeExpo extends ExpoProvider {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
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
  const f = await fixture(t, { gmail, integrations: [expoConnection(expo), gmailConnection(gmail)], ...options });
  const importExpo = (extra = {}, requestOptions = {}) => f.request('/api/connections/expo/connect', { method: 'POST', data: { name: 'Expo', mode: 'access-token', token: expo.tokenValue(), ...extra }, ...requestOptions });
  async function expoAccount(extra = {}) {
    const result = await importExpo(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.accounts.find(account => account.id === result.json.account_id);
  }
  return { ...f, expo, importExpo, expoAccount };
}
