import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

async function oauthFixture() {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  const owner = await f.person();
  return { f, app, owner, origin: f.config.origin, close: async () => { await app.close(); await f.close(); } };
}
const mcpHeaders = { accept: 'application/json, text/event-stream', 'content-type': 'application/json' };
const initialize = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'Claude', version: '1' } },
};

test('MCPのOAuthで登録・承認・発行した鍵により、承認したプリンシパルとしてMCPを使う', async t => {
  const { app, owner, origin, close } = await oauthFixture(); t.after(close);
  const unauthenticated = await app.inject({ method: 'POST', url: '/api/mcp', headers: mcpHeaders, payload: initialize });
  assert.equal(unauthenticated.statusCode, 401);
  assert.match(String(unauthenticated.headers['www-authenticate']), /resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource\/api\/mcp"/);
  const resource = (await app.inject('/.well-known/oauth-protected-resource/api/mcp')).json();
  assert.equal(resource.resource, origin + '/api/mcp');
  const server = (await app.inject('/.well-known/oauth-authorization-server')).json();
  assert.deepEqual(server.code_challenge_methods_supported, ['S256']);

  const redirectUri = 'https://claude.ai/api/mcp/auth_callback';
  const registered = await app.inject({ method: 'POST', url: '/api/oauth/register',
    payload: { client_name: 'Claude', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' } });
  assert.equal(registered.statusCode, 201, registered.body);
  const clientId = registered.json().client_id;
  const verifier = randomBytes(32).toString('base64url'),
    codeChallenge = createHash('sha256').update(verifier).digest('base64url');
  const headers = { authorization: 'Bearer ' + owner.token };
  const described = await app.inject({ url: '/api/oauth/client?' + new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri }), headers });
  assert.deepEqual(described.json(), { name: 'Claude', host: 'claude.ai' });
  const approve = () => app.inject({ method: 'POST', url: '/api/oauth/authorizations', headers, payload: {
    clientId, redirectUri, codeChallenge, codeChallengeMethod: 'S256', state: 'xyz', resource: origin + '/api/mcp', principalId: owner.actor.id,
  } });
  const approved = await approve();
  assert.equal(approved.statusCode, 200, approved.body);
  const returned = new URL(approved.json().redirectTo);
  assert.equal(returned.origin + returned.pathname, redirectUri);
  assert.equal(returned.searchParams.get('state'), 'xyz');
  const exchange = (code: string, codeVerifier: string) => app.inject({ method: 'POST', url: '/api/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: codeVerifier,
      redirect_uri: redirectUri, client_id: clientId, resource: origin + '/api/mcp' }).toString() });
  const issued = await exchange(returned.searchParams.get('code')!, verifier);
  assert.equal(issued.statusCode, 200, issued.body);
  assert.equal(issued.json().token_type, 'Bearer');
  assert.equal((await exchange(returned.searchParams.get('code')!, verifier)).json().error, 'invalid_grant');

  const connected = await app.inject({ method: 'POST', url: '/api/mcp', payload: initialize,
    headers: { ...mcpHeaders, authorization: 'Bearer ' + issued.json().access_token } });
  assert.equal(connected.statusCode, 200, connected.body);
  assert.equal(connected.json().result.serverInfo.name, 'Foundation');
  const keys = await app.inject({ url: '/api/principals/' + owner.actor.id + '/credentials', headers });
  assert.ok(keys.json().items.some((item: { name: string }) => item.name === 'Claude'));

  const another = new URL((await approve()).json().redirectTo).searchParams.get('code')!;
  assert.equal((await exchange(another, randomBytes(32).toString('base64url'))).json().error, 'invalid_grant');
});

test('MCPのOAuthは登録していない戻り先と、承認する権限のないプリンシパルを断る', async t => {
  const { app, f, owner, close } = await oauthFixture(); t.after(close);
  const stranger = await f.person();
  const registered = (await app.inject({ method: 'POST', url: '/api/oauth/register',
    payload: { client_name: 'Claude', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] } })).json();
  assert.equal((await app.inject({ method: 'POST', url: '/api/oauth/register',
    payload: { redirect_uris: ['http://example.com/callback'] } })).statusCode, 400);
  const payload = { clientId: registered.client_id, codeChallenge: randomBytes(32).toString('base64url'),
    codeChallengeMethod: 'S256', principalId: owner.actor.id };
  const elsewhere = await app.inject({ method: 'POST', url: '/api/oauth/authorizations',
    headers: { authorization: 'Bearer ' + owner.token }, payload: { ...payload, redirectUri: 'https://attacker.example/callback' } });
  assert.equal(elsewhere.statusCode, 400);
  const forbidden = await app.inject({ method: 'POST', url: '/api/oauth/authorizations',
    headers: { authorization: 'Bearer ' + stranger.token },
    payload: { ...payload, redirectUri: 'https://claude.ai/api/mcp/auth_callback' } });
  assert.equal(forbidden.statusCode, 403);
});
