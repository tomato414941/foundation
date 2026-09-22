import { CloudflareClient, CLOUDFLARE_API } from '../src/services/cloudflare.mjs';
import { cloudflareApiToken, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export const CLOUDFLARE_TOKEN = 'cfut_' + 'fixturetoken'.repeat(4);
export const CLOUDFLARE_ACCOUNT = '1234567890abcdef1234567890abcdef';
export class FakeCloudflare extends CloudflareClient {
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
    return json({ success: false }, 403);
  }
}

export async function cloudflareFixture(t, options = {}) {
  const cloudflare = options.cloudflare || new FakeCloudflare(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, adapters: [cloudflareApiToken(cloudflare), gmailReadonly(gmail), gmailMetadata(gmail)], ...options });
  const importCloudflare = ({ token = CLOUDFLARE_TOKEN, fields = { account_id: CLOUDFLARE_ACCOUNT }, ...extra } = {}) => f.request('/api/adapters/cloudflare.api-token/connect', { method: 'POST', data: { name: 'Cloudflare', values: { account_id: fields.account_id, token }, ...extra } });
  async function cloudflareAccount(extra = {}) {
    const result = await importCloudflare(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.credentials.find(account => account.id === result.json.credential_id);
  }
  return { ...f, cloudflare, importCloudflare, cloudflareAccount };
}
