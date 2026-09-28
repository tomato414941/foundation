import { GoogleClient } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

// Answers as Google would. The authorization code names the account, and Google grants what the consent screen
// asked for unless a test sets `scopes`. Handlers may answer instead, by returning a Response.
export class FakeGoogle extends GoogleClient {
  constructor() {
    super({ clientId: 'test-google-client', clientSecret: 'test-google-secret' }, { fetcher: async (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchanges = 0; this.refreshes = 0; this.scopes = null; this.consent = { asked: [] }; this.granted = new Map();
  }
  // Shared with the copies made for someone's own app, which ask for consent through the same fake.
  authorize(context) { this.consent.asked = context.scopes; return super.authorize(context); }
  async fetch(url, options) {
    this.calls.push({ url: String(url), options });
    if (String(url).endsWith('/revoke')) return await this.revokeHandler?.() || new Response('', { status: 200 });
    if (String(url).endsWith('/token')) {
      const params = options.body, exchange = params.get('grant_type') === 'authorization_code';
      const code = exchange ? params.get('code') : params.get('refresh_token').replace('refresh-', '');
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = await (exchange ? this.exchangeHandler?.(params) : this.refreshHandler?.(params));
      if (handled) return handled;
      if (exchange) this.granted.set(code, this.scopes ?? this.consent.asked.join(' '));
      const scope = this.scopes ?? this.granted.get(code) ?? 'openid';
      return json({ access_token: 'google-access-' + code + (this.refreshes && !exchange ? '-' + this.refreshes : ''), refresh_token: 'refresh-' + code,
        expires_in: 3600, scope, token_type: 'Bearer' });
    }
    if (String(url).includes('/userinfo')) {
      const account = options.headers.authorization.replace(/^Bearer google-access-/, '').replace(/-\d+$/, '');
      return await this.userinfoHandler?.(account) || json({ sub: 'sub-' + account, email: account + '@example.test', email_verified: true });
    }
    throw new Error('Unexpected provider request');
  }
}
