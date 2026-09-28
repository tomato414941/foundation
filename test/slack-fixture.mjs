import { definitionOf } from '../src/catalog.mjs';
import { oauthClient, oauthScheme } from '../src/schemes/oauth.mjs';
import { tokenScheme } from '../src/schemes/token.mjs';
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: typeof body === 'string' ? body : JSON.stringify(body) });
const TEAMS = { personal: { id: 'T0PERSONAL', name: '個人のワークスペース' }, work: { id: 'T0WORK', name: '仕事のワークスペース' } };

// Slack's Web API as far as connecting goes: oauth.v2.access, auth.test and auth.revoke, answering with "ok" in the
// body. The code names the workspace; tokens rotate only when a test turns it on.
export class FakeSlack {
  constructor({ configured = true } = {}) {
    this.calls = []; this.exchanges = 0; this.refreshes = 0; this.revoked = new Set(); this.rotating = false; this.asked = [];
    this.client = oauthClient(definitionOf('slack'), configured ? { clientId: 'test-slack-client', clientSecret: 'test-slack-secret' } : {}, { fetcher: (url, options) => this.answer(url, options) });
  }
  // Slack grants the bot scopes its consent screen asked for; the fake learns them as the consent screen would.
  entry() {
    const definition = definitionOf('slack'), oauth = oauthScheme(definition, this.client);
    return { definition, schemes: { oauth: { ...oauth, authorization: { ...oauth.authorization, begin: context => { this.asked = context.scopes; return oauth.authorization.begin(context); } } },
      token: tokenScheme(definition, { fetcher: (url, options) => this.answer(url, options) }) } };
  }
  async answer(url, options = {}) {
    this.calls.push({ url, options });
    const method = url.replace('https://slack.com/api/', '').replace(/^https:\/\/slack\.com\/oauth\/v2\/authorize.*/, 'authorize');
    const body = new URLSearchParams(options.body ?? ''), token = options.headers?.authorization?.replace(/^Bearer /, '');
    if (method === 'oauth.v2.access') {
      const exchange = body.get('grant_type') !== 'refresh_token';
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = await this.tokenHandler?.(body);
      if (handled) return reply(200, handled);
      if (!exchange && this.revoked.has(body.get('refresh_token'))) return reply(200, { ok: false, error: 'invalid_refresh_token' });
      const team = exchange ? body.get('code') : body.get('refresh_token').split('-')[2];
      if (!TEAMS[team]) return reply(200, { ok: false, error: 'invalid_code' });
      const suffix = this.exchanges + '-' + this.refreshes;
      return reply(200, { ok: true, access_token: 'xoxb-' + team + '-' + suffix, token_type: 'bot', scope: this.asked.join(','), bot_user_id: 'U0BOT', team: TEAMS[team],
        ...(this.rotating ? { expires_in: 43200, refresh_token: 'xoxe-refresh-' + team + '-' + suffix } : {}) });
    }
    if (method === 'auth.test') {
      if (!token || this.revoked.has(token)) return reply(200, { ok: false, error: 'invalid_auth' });
      const team = TEAMS[token.split('-')[1]];
      return reply(200, { ok: true, url: 'https://' + team.id.toLowerCase() + '.slack.com/', team: team.name, team_id: team.id, user_id: 'U0BOT', bot_id: 'B0BOT' });
    }
    if (method === 'auth.revoke') {
      const handled = await this.revokeHandler?.(token);
      if (handled) return reply(200, handled);
      this.revoked.add(token);
      return reply(200, { ok: true, revoked: true });
    }
    throw new Error('Unexpected Slack fixture request: ' + url);
  }
}
