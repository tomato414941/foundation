import { GmailClient, METADATA_SCOPE, READONLY_SCOPE, SEND_SCOPE } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

export class FakeGmail extends GmailClient {
  constructor() {
    super({ clientId: 'test-google-client', clientSecret: 'test-google-secret' }, { fetcher: async (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchangeCount = 0;
  }
  async fetch(url, options) {
    this.calls.push({ url: String(url), options });
    if (String(url).endsWith('/revoke')) {
      if (this.revokeHandler) return this.revokeHandler();
      return new Response('', { status: 200 });
    }
    if (String(url).endsWith('/token')) {
      const params = options.body, exchange = params.get('grant_type') === 'authorization_code';
      const code = exchange ? params.get('code') : params.get('refresh_token').replace('refresh-', '');
      if (exchange) { this.exchangeCount++; if (this.exchangeHandler) await this.exchangeHandler(); }
      else if (this.refreshHandler) { const result = await this.refreshHandler(); if (result) return result; }
      const scope = code.endsWith('-metadata') ? METADATA_SCOPE : code.endsWith('-read-send') ? READONLY_SCOPE + ' ' + SEND_SCOPE : READONLY_SCOPE;
      return json({ access_token: 'google-access-' + code, refresh_token: 'refresh-' + code, expires_in: 3600, scope, token_type: 'Bearer' });
    }
    if (String(url).includes('/profile?')) {
      const code = options.headers.authorization.replace('Bearer google-access-', '');
      const email = code.replace(/-(readonly|metadata|read-send)$/, '') + '@example.test';
      return json({ emailAddress: email });
    }
    throw new Error('Unexpected provider request');
  }
}
