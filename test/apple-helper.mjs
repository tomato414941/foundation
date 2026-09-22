import { createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { AppleClient, APPLE_API } from '../src/services/apple.mjs';
import { appleApiKey, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

// A fixed test key so every process (unit tests, fixture server, browser tests) agrees on it. Never used outside tests.
export const APPLE_P8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg34+bpdwxPaVozudq
WOg4Bi3ewoewJVfOzGh6nwC8ctuhRANCAATmdoPjzakFeKK2uqXjMiQwf/chhlWt
6kHVcyP2Fg3clMqoO549aG39yI9sFoT9+fpeI4JN/wH7uhFdygSo1HGv
-----END PRIVATE KEY-----
`;
const pair = { privateKey: createPrivateKey(APPLE_P8), publicKey: createPublicKey(createPrivateKey(APPLE_P8)) };
export const APPLE_FIELDS = { key_id: 'ABC1234567', issuer_id: '69a6de70-03db-47e3-e053-5b8c7c11a4d1', team_id: 'TEAM123456', team_type: 'INDIVIDUAL' };

// Verifies the JWT Foundation signs, exactly as App Store Connect would, but never contacts Apple.
export class FakeApple extends AppleClient {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.publicKey = pair.publicKey; this.apps = [{ id: '1', attributes: { bundleId: 'com.example.app' } }];
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (!url.startsWith(APPLE_API + '/apps') || (options.method && options.method !== 'GET')) throw new Error('Only the app list probe is allowed in tests: ' + url);
    if (this.handler) return this.handler(url, options);
    const jwt = options.headers.authorization?.slice(7) || '', [header, payload, signature] = jwt.split('.');
    if (!header || !payload || !signature) return json({ errors: [{ status: '401' }] }, 401);
    const decoded = part => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    const head = decoded(header), claims = decoded(payload);
    const valid = head.alg === 'ES256' && head.kid === APPLE_FIELDS.key_id && claims.iss === APPLE_FIELDS.issuer_id && claims.aud === 'appstoreconnect-v1'
      && claims.exp - claims.iat <= 1200 && verify('sha256', Buffer.from(header + '.' + payload), { key: this.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'));
    if (!valid) return json({ errors: [{ status: '401', code: 'NOT_AUTHORIZED' }] }, 401);
    return json({ data: this.apps });
  }
}

export async function appleFixture(t, options = {}) {
  const apple = options.apple || new FakeApple(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, adapters: [appleApiKey(apple), gmailReadonly(gmail), gmailMetadata(gmail)], ...options });
  const importApple = ({ token = APPLE_P8, fields = APPLE_FIELDS, ...extra } = {}) => f.request('/api/adapters/apple.api-key/connect', { method: 'POST', data: { name: 'Apple', values: { ...fields, key: token }, ...extra } });
  async function appleAccount(extra = {}) {
    const result = await importApple(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.credentials.find(account => account.id === result.json.credential_id);
  }
  return { ...f, apple, importApple, appleAccount };
}
