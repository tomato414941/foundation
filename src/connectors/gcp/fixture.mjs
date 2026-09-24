import { GcpClient, GCP_SCOPES } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

export class FakeGcp extends GcpClient {
  constructor() {
    super({ clientId: 'test-gcp-client', clientSecret: 'test-gcp-secret' }, { fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchanges = 0; this.refreshes = 0;
    this.scopes = GCP_SCOPES.join(' ');
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url.endsWith('/revoke')) return this.revokeHandler?.() || new Response('', { status: 200 });
    if (url.endsWith('/token')) {
      const exchange = options.body.get('grant_type') === 'authorization_code';
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = exchange ? await this.exchangeHandler?.(options.body) : await this.refreshHandler?.(options.body);
      if (handled) return handled;
      const account = exchange ? options.body.get('code') : options.body.get('refresh_token').split('-')[2];
      return json({ access_token: 'gcp-access-' + account + '-' + this.refreshes, refresh_token: 'gcp-refresh-' + account,
        scope: this.scopes, expires_in: 3600, token_type: 'Bearer' });
    }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      const account = options.headers.authorization.split('-')[2];
      return this.identityHandler?.(account) || json({ sub: account === 'work' ? '1002' : '1001', email: account + '@example.test', email_verified: true });
    }
    throw new Error('Unexpected GCP fixture request');
  }
}
