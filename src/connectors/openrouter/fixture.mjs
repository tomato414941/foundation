import { createHash } from 'node:crypto';
import { OpenRouterClient } from './client.mjs';
import { openrouterOauth } from './index.mjs';
import { gmailReadonly, gmailMetadata } from '../gmail/index.mjs';
import { FakeGmail, fixture, json } from '../../../test/helpers.mjs';

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
  const openrouter = options.openrouter || new FakeOpenRouter(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, connectors: [openrouterOauth(openrouter), gmailReadonly(gmail), gmailMetadata(gmail)], ...options });
  async function start(extra = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { connector: 'openrouter.oauth', ...extra } });
    if (result.status !== 200) throw new Error(result.text);
    return new URL(result.json.url);
  }
  async function callback(url, code = 'personal', options = {}) {
    const target = new URL(url.searchParams.get('callback_url'));
    target.searchParams.set('code', code);
    return f.request(target.pathname + target.search, options);
  }
  async function account(code = 'personal') {
    const result = await callback(await start(), code);
    if (!result.headers.get('location')?.includes('connection=connected')) throw new Error(result.headers.get('location'));
    const state = (await f.request('/v1/state')).json;
    return state.connections.filter(item => item.connector === 'openrouter.oauth').at(-1);
  }
  const deliver = (connection, options) => f.request('/v1/functions/connection.credentials', { method: 'POST', data: { connection_id: connection.id }, ...options });
  return { ...f, openrouter, startOpenRouter: start, callbackOpenRouter: callback, openrouterAccount: account, deliver };
}
