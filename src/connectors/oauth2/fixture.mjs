import { genericClient } from './index.mjs';

// A service that speaks plain OAuth 2.0, at https://service.example. The authorization code names the account; tokens
// carry a counter so refreshes can be told apart. Handlers may answer instead, by returning { status, body }.
export const SERVICE = { authorize_url: 'https://service.example/oauth/authorize', token_url: 'https://service.example/oauth/token',
  userinfo_url: 'https://service.example/api/me', revoke_url: 'https://service.example/oauth/revoke' };

export class FakeOAuth2Service {
  constructor() {
    this.calls = []; this.refreshes = 0; this.revoked = new Set(); this.expiresIn = 3600; this.scope = undefined;
    this.fetch = async (url, options = {}) => this.answer(url, options);
  }
  client() { return genericClient(this.fetch); }
  reply(status, body) { return { ok: status >= 200 && status < 300, status, text: typeof body === 'string' ? body : JSON.stringify(body) }; }
  async answer(url, options) {
    this.calls.push({ url, options });
    if (url === SERVICE.token_url) {
      const params = new URLSearchParams(options.body), exchange = params.get('grant_type') === 'authorization_code';
      const handled = await (exchange ? this.exchangeHandler?.(params) : this.refreshHandler?.(params));
      if (handled) return this.reply(handled.status, handled.body);
      if (!exchange) this.refreshes++;
      const account = exchange ? params.get('code') : params.get('refresh_token').replace(/^refresh-/, '');
      if (!exchange && this.revoked.has(params.get('refresh_token'))) return this.reply(400, { error: 'invalid_grant' });
      return this.reply(200, { access_token: 'access-' + account + '-' + this.refreshes, token_type: 'Bearer', refresh_token: 'refresh-' + account,
        ...(this.expiresIn === null ? {} : { expires_in: this.expiresIn }), ...(this.scope === undefined ? {} : { scope: this.scope }) });
    }
    if (url === SERVICE.userinfo_url) {
      const account = options.headers.authorization.replace(/^Bearer access-/, '').replace(/-\d+$/, '');
      return this.reply(200, await this.userinfoHandler?.(account) ?? { id: 'id-' + account, email: account + '@service.example' });
    }
    if (url === SERVICE.revoke_url) { this.revoked.add(new URLSearchParams(options.body).get('token')); return this.reply(200, ''); }
    throw new Error('Unexpected request to ' + url);
  }
}
