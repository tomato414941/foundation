import { SlackClient, SLACK_API } from './client.mjs';
import { json } from '../../../test/helpers.mjs';

const TEAMS = { personal: { id: 'T0PERSONAL', name: '個人のワークスペース' }, work: { id: 'T0WORK', name: '仕事のワークスペース' } };

export class FakeSlack extends SlackClient {
  constructor() {
    super({ clientId: 'test-slack-client', clientSecret: 'test-slack-secret' }, { fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.exchanges = 0; this.refreshes = 0; this.revoked = new Set();
    // Like Slack, grants the bot scopes the consent screen asked for. Tokens rotate only when a test turns it on.
    this.rotating = false; this.consent = { asked: [] };
  }
  // Shared with the copies made for someone's own app, which ask for consent through the same fake.
  authorize(context) { this.consent.asked = context.scopes; return super.authorize(context); }
  async fetch(url, options) {
    this.calls.push({ url, options });
    const method = url.slice(SLACK_API.length + 1), body = options.body, token = options.headers.authorization?.slice('Bearer '.length);
    if (method === 'oauth.v2.access') {
      const exchange = body.get('grant_type') !== 'refresh_token';
      if (exchange) this.exchanges++; else this.refreshes++;
      const handled = await this.tokenHandler?.(body);
      if (handled) return handled;
      if (body.get('client_secret') === 'wrong') return json({ ok: false, error: 'bad_client_secret' });
      if (!exchange && this.revoked.has(body.get('refresh_token'))) return json({ ok: false, error: 'invalid_refresh_token' });
      const team = exchange ? body.get('code') : body.get('refresh_token').split('-')[2];
      if (!TEAMS[team]) return json({ ok: false, error: 'invalid_code' });
      const suffix = this.exchanges + '-' + this.refreshes;
      return json({ ok: true, access_token: 'xoxb-' + team + '-' + suffix, token_type: 'bot', scope: this.consent.asked.join(','), bot_user_id: 'U0BOT',
        team: TEAMS[team], ...(this.rotating ? { expires_in: 43200, refresh_token: 'xoxe-refresh-' + team + '-' + suffix } : {}) });
    }
    if (method === 'auth.test') {
      if (!token || this.revoked.has(token)) return json({ ok: false, error: 'invalid_auth' });
      const team = TEAMS[token.split('-')[1]];
      return await this.identityHandler?.(team) || json({ ok: true, url: 'https://' + team.id.toLowerCase() + '.slack.com/', team: team.name, team_id: team.id, user_id: 'U0BOT', bot_id: 'B0BOT' });
    }
    if (method === 'auth.revoke') {
      const handled = await this.revokeHandler?.(token);
      if (handled) return handled;
      this.revoked.add(token);
      return json({ ok: true, revoked: true });
    }
    throw new Error('Unexpected Slack fixture request');
  }
}
