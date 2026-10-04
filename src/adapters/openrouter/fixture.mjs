import { createHash } from 'node:crypto';
import { OpenRouterClient } from './client.mjs';
import { openrouterOauth } from './index.mjs';
import { googleOauth } from '../google/index.mjs';
import { FakeGoogle, fixture, json, entry } from '../../../test/helpers.mjs';

export class FakeOpenRouter extends OpenRouterClient {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
    this.calls = [];
    this.info = { is_management_key: false, is_provisioning_key: false, limit: 0, limit_remaining: 0, limit_reset: null, include_byok_in_limit: true, expires_at: null };
  }
  key(code = 'personal') { return 'sk-or-v1-' + createHash('sha256').update('fixture:' + code).digest('hex'); }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url.endsWith('/auth/keys') && options.method === 'POST') {
      if (this.exchangeHandler) return this.exchangeHandler(url, options);
      return json({ key: this.key(JSON.parse(options.body).code), user_id: 'fixture-owner' });
    }
    if (url.endsWith('/key') && (!options.method || options.method === 'GET')) {
      if (this.keyHandler) return this.keyHandler(url, options);
      return json({ data: this.info });
    }
    throw new Error('Unexpected outbound request: model, billing and management endpoints are forbidden in this fixture');
  }
}

export async function openrouterFixture(t, options = {}) {
  const openrouter = options.openrouter || new FakeOpenRouter(), google = new FakeGoogle();
  const f = await fixture(t, { google, services: [entry('openrouter', { oauth: openrouterOauth(openrouter) }), entry('google', { oauth: googleOauth(google) })], ...options });
  // Begun by the owner, or by answering a request for it.
  async function start(extra = {}) {
    const result = extra.request_id ? await f.request('/v1/requests/' + extra.request_id + '/grant', { method: 'POST', data: {} })
      : await f.request('/v1/principals/me/connections', { method: 'POST', data: { service: 'openrouter', ...extra } });
    if (result.status !== 200) throw new Error(result.text);
    return new URL(extra.request_id ? result.json.continue.url : result.json.url);
  }
  async function callback(url, code = 'personal', options = {}) {
    const target = new URL(url.searchParams.get('callback_url'));
    target.searchParams.set('code', code);
    return f.request(target.pathname + target.search, options);
  }
  async function account(code = 'personal') {
    const result = await callback(await start(), code);
    if (!result.headers.get('location')?.includes('result=connected')) throw new Error(result.headers.get('location'));
    const listed = (await f.request('/v1/principals/me/resources?kind=connection')).json.resources;
    return listed.filter(item => item.service?.id === 'openrouter').at(-1);
  }
  return { ...f, openrouter, startOpenRouter: start, callbackOpenRouter: callback, openrouterAccount: account };
}
