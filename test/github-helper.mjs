import { GitHubClient, GITHUB_SCOPES } from '../src/services/github.mjs';
import { json } from './helpers.mjs';

// Answers as GitHub would for a few accounts; every other outbound request is refused.
export class FakeGitHub extends GitHubClient {
  constructor() {
    super({ clientId: 'Iv1.fixture', clientSecret: 'fixture-secret' }, { fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.revoked = new Set(); this.scopes = GITHUB_SCOPES.join(', ');
    this.users = { octo: { id: 1001, login: 'octo' }, other: { id: 2002, login: 'other' } };
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url === 'https://github.com/login/oauth/access_token' && options.method === 'POST') {
      const body = JSON.parse(options.body);
      if (body.client_secret !== 'fixture-secret' || !body.code_verifier) return json({ error: 'incorrect_client_credentials' });
      if (!this.users[body.code]) return json({ error: 'bad_verification_code' });
      return json({ access_token: 'gho_' + body.code, token_type: 'bearer', scope: this.scopes });
    }
    if (url === 'https://api.github.com/user') {
      const token = options.headers.authorization.replace('Bearer ', ''), user = this.users[token.replace('gho_', '')];
      if (!user || this.revoked.has(token)) return json({ message: 'Bad credentials' }, 401);
      return new Response(JSON.stringify(user), { status: 200, headers: { 'content-type': 'application/json', 'x-oauth-scopes': this.scopes } });
    }
    if (url === 'https://api.github.com/applications/Iv1.fixture/grant' && options.method === 'DELETE') {
      if (options.headers.authorization !== 'Basic ' + Buffer.from('Iv1.fixture:fixture-secret').toString('base64')) return json({}, 401);
      this.revoked.add(JSON.parse(options.body).access_token);
      return new Response(null, { status: 204 });
    }
    throw new Error('Unexpected outbound request: ' + url);
  }
}
