import { CloudflareClient, CLOUDFLARE_API, CLOUDFLARE_SCOPES } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

export class FakeCloudflare extends CloudflareClient {
  constructor() {
    super({ clientId: 'test-cloudflare-client', clientSecret: 'test-cloudflare-secret' }, { fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchanges = 0; this.refreshes = 0; this.revoked = new Set();
    this.scopes = CLOUDFLARE_SCOPES.join(' ');
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url.endsWith('/revoke')) {
      const handled = await this.revokeHandler?.(options.body);
      if (handled) return handled;
      this.revoked.add(options.body.get('token'));
      return new Response('', { status: 200 });
    }
    if (url === CLOUDFLARE_API + '/user') {
      const token = options.headers.authorization.slice('Bearer '.length), account = token.split('-')[2];
      if (this.revoked.has(token)) return json({ success: false }, 401);
      return await this.identityHandler?.(account) || json({ success: true, result: {
        id: (account === 'work' ? '2' : '1').repeat(32), email: account + '@example.test' } });
    }
    if (url.endsWith('/token')) {
      const exchange = options.body.get('grant_type') === 'authorization_code';
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = await (exchange ? this.exchangeHandler?.(options.body) : this.refreshHandler?.(options.body));
      if (handled) return handled;
      const account = exchange ? options.body.get('code') : options.body.get('refresh_token').split('-')[2];
      if (!exchange && this.revoked.has(options.body.get('refresh_token'))) return json({ error: 'invalid_grant' }, 400);
      return json({ access_token: 'cf-access-' + account + '-' + this.refreshes, refresh_token: 'cf-refresh-' + account + '-' + this.refreshes,
        token_type: 'Bearer', expires_in: 3600, scope: this.scopes });
    }
    throw new Error('Unexpected Cloudflare fixture request');
  }
}
