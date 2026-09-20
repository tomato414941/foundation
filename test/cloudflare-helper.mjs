import { CloudflareProvider, CLOUDFLARE_API } from '../src/providers/cloudflare.mjs';
import { cloudflareConnection, gmailConnection } from '../src/providers/catalog.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export const CLOUDFLARE_TOKEN = 'cfut_' + 'fixturetoken'.repeat(4);
export const CLOUDFLARE_ACCOUNT = '1234567890abcdef1234567890abcdef';
export class FakeCloudflare extends CloudflareProvider {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
    this.calls = [];
    this.valid = new Set([CLOUDFLARE_TOKEN]);
    this.verification = { id: 'abcdef1234567890abcdef1234567890', status: 'active', expires_on: '2099-01-01T00:00:00Z' };
    this.buckets = [{ name: 'test-bucket-do-not-store' }];
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (!url.startsWith(CLOUDFLARE_API + '/') || options.method !== 'GET' || options.body) throw new Error('Only official Cloudflare reads are allowed in tests');
    if (this.handler) {
      const response = await this.handler(url, options);
      if (response) return response;
    }
    if (!this.valid.has(options.headers.authorization?.slice(7))) return json({ success: false }, 401);
    if (url.endsWith('/user/tokens/verify')) return json({ success: true, result: this.verification });
    if (url === CLOUDFLARE_API + '/accounts/' + CLOUDFLARE_ACCOUNT + '/r2/buckets?per_page=1') return json({ success: true, result: { buckets: this.buckets } });
    return json({ success: false }, 403);
  }
}

export async function cloudflareFixture(t, options = {}) {
  const cloudflare = options.cloudflare || new FakeCloudflare(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, integrations: [cloudflareConnection(cloudflare), gmailConnection(gmail)], ...options });
  const importCloudflare = (extra = {}) => f.request('/api/connections/cloudflare/connect', { method: 'POST', data: { name: 'Cloudflare', mode: 'api-token', token: CLOUDFLARE_TOKEN, fields: { account_id: CLOUDFLARE_ACCOUNT }, ...extra } });
  async function cloudflareAccount(extra = {}) {
    const result = await importCloudflare(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.accounts.find(account => account.id === result.json.account_id);
  }
  return { ...f, cloudflare, importCloudflare, cloudflareAccount };
}
