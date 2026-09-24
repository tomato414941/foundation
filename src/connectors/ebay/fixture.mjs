import { EbayClient, EBAY_API, EBAY_SCOPES } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

export class FakeEbay extends EbayClient {
  constructor() {
    super({ clientId: 'test-ebay-client', clientSecret: 'test-ebay-secret', ruName: 'Test-Foundation-RuName' }, { fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchanges = 0; this.refreshes = 0;
    this.scopes = EBAY_SCOPES.join(' ');
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url.endsWith('/revoke')) return this.revokeHandler?.(options.body) || new Response('', { status: 200 });
    if (url.endsWith('/introspect')) {
      const account = options.body.get('token').split('-')[2];
      return this.inspectHandler?.(account, options.body) || json({ active: true, sub: account === 'work' ? '1002' : '1001', username: account + '-seller',
        scope: this.scopes, client_id: this.clientId, exp: Math.floor(Date.now() / 1000) + 7200, token_type: 'Bearer', aud: EBAY_API, iss: EBAY_API + '/identity' });
    }
    if (url.endsWith('/token')) {
      const exchange = options.body.get('grant_type') === 'authorization_code';
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = exchange ? await this.exchangeHandler?.(options.body) : await this.refreshHandler?.(options.body);
      if (handled) return handled;
      const account = exchange ? options.body.get('code') : options.body.get('refresh_token').split('-')[2];
      return json({ access_token: 'ebay-access-' + account + '-' + this.refreshes, expires_in: 7200, token_type: 'User Access Token',
        ...(exchange ? { refresh_token: 'ebay-refresh-' + account, refresh_token_expires_in: 47304000 } : {}) });
    }
    throw new Error('Unexpected eBay fixture request');
  }
}
