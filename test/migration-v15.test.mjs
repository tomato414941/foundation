import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault, digest } from '../src/crypto.mjs';
import { fixture, resources, FakeAuth, KEY, USER_A, USER_B } from './helpers.mjs';
import { READONLY_SCOPE } from '../src/connectors/gmail/client.mjs';

// A frozen production-era schema, independent of the migration implementation.
const V15 = `
CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE keys(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,name TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,last_used_at TEXT,issued_until INTEGER,issued_nonexpiring INTEGER NOT NULL DEFAULT 0);
CREATE TABLE sessions(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,email TEXT NOT NULL,secret TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE oauth_flows(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,payload TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE key_requests(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,name TEXT NOT NULL,confirmation_code TEXT NOT NULL,confirmation_attempts INTEGER NOT NULL DEFAULT 0,progress TEXT,owner_id TEXT,key_id TEXT,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX key_requests_token ON key_requests(token_hash,created_at);
CREATE TABLE requests(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,key_id TEXT NOT NULL,owner_id TEXT NOT NULL,requester_name TEXT NOT NULL,adapter TEXT,purpose TEXT NOT NULL,details TEXT NOT NULL,steps TEXT NOT NULL,progress TEXT,credential_id TEXT,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX requests_token ON requests(token_hash,created_at);
CREATE TABLE secrets(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,readable INTEGER NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(owner_id,name));
CREATE INDEX secrets_owner ON secrets(owner_id,name);
CREATE TABLE acquisitions(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,adapter TEXT NOT NULL,subject TEXT NOT NULL,label TEXT NOT NULL,state TEXT NOT NULL,status TEXT NOT NULL,generation INTEGER NOT NULL DEFAULT 1,kept_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(owner_id,adapter,subject));
CREATE INDEX acquisitions_owner ON acquisitions(owner_id,id);
CREATE TABLE integrations(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,name TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,return_url TEXT NOT NULL,created_at TEXT NOT NULL,last_used_at TEXT,refresh_url TEXT,webhook_url TEXT,webhook_secret TEXT);
CREATE TABLE accounts(id TEXT PRIMARY KEY,integration_id TEXT NOT NULL,external_id TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(integration_id,external_id));
CREATE TABLE request_links(token_hash TEXT PRIMARY KEY,request_id TEXT NOT NULL,owner_id TEXT NOT NULL,kind TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE invocations(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,key_id TEXT,key_name TEXT NOT NULL,function TEXT NOT NULL,target TEXT NOT NULL,status TEXT NOT NULL,detail TEXT NOT NULL,at TEXT NOT NULL);
CREATE INDEX invocations_owner ON invocations(owner_id,at);
PRAGMA user_version=15;
`;

async function previous(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-v15-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(V15);
  const at = Date.now(), until = at + 3600_000, stamp = '2026-09-24T00:00:00.000Z';
  const token = 'fdn_' + 'k'.repeat(43), sessionToken = 's'.repeat(43), flowToken = 'f'.repeat(43), keyId = 'existing-key';
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('wrapped_key', 'fixture-encrypted-envelope');
  db.prepare('INSERT INTO keys VALUES (?,?,?,?,?,?,?,?)').run(keyId, USER_A, 'Existing AI', digest(token), stamp, stamp, until, 1);
  const auth = new FakeAuth().value();
  db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)').run(digest(sessionToken), USER_A, auth.user.email, vault.seal(auth, 'session:' + digest(sessionToken)), until);
  const entries = [];
  for (const owner of [USER_A, USER_B]) for (const [index, name] of ['safdgaae', 'a/aa/aaa', 'with, comma'].entries()) {
    const id = owner + ':' + index, content = Buffer.from([0, 255, index]), ciphertext = vault.sealBytes(content, `entry:${owner}:${id}`);
    db.prepare('INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?)').run(id, owner, name, content.length, index % 2, ciphertext, stamp, stamp);
    entries.push({ owner, id, name, content, ciphertext, readable: index % 2 === 1 });
  }
  const connectionId = 'existing-connection';
  const privateState = { access_token: 'google-access-personal-readonly', refresh_token: 'refresh-personal-readonly', scopes: [READONLY_SCOPE], expires_at: until };
  const state = { private_state: privateState, facts: { label: 'Personal' }, expires_at: until };
  db.prepare('INSERT INTO acquisitions VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(connectionId, USER_A, 'gmail.readonly', 'personal@example.test', 'Personal', vault.seal(state, `acquisition:${USER_A}:${connectionId}`), 'connected', 7, 'Existing AI', stamp, stamp);
  const ids = { connect: 'c'.repeat(43), store: 'd'.repeat(43), pending: 'p'.repeat(43), revoked: 'r'.repeat(43), revokedDone: 'x'.repeat(43), approval: 'a'.repeat(43) };
  for (const name of ['connect', 'store', 'pending', 'revoked', 'revokedDone']) {
    const connect = name !== 'store', done = ['connect', 'store', 'revokedDone'].includes(name), revoked = name.startsWith('revoked');
    db.prepare('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(ids[name], revoked ? digest('fdn_' + 'z'.repeat(43)) : digest(token), revoked ? 'removed-key' : keyId, USER_A, 'Existing AI',
      connect ? 'gmail.readonly' : null, '既存の依頼', connect ? '[]' : JSON.stringify([{ name: 'with, comma', label: '値', secret: true, site: '', multiline: false }]), '[]', '[{"event":"page_viewed","at":1}]',
      done ? connect ? connectionId : '["with, comma"]' : null, done ? 'done' : 'pending', at, until);
  }
  db.prepare('INSERT INTO key_requests (id,token_hash,name,confirmation_code,owner_id,key_id,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)').run(ids.approval, digest(token), 'Existing AI', '1234-ABCD', USER_A, keyId, 'approved', at, until);
  const flow = { adapter: 'gmail.readonly', verifier: 'fixture-verifier', redirectUri: 'https://example.test/oauth/gmail.readonly/callback', requestId: ids.pending, previous: { id: connectionId, generation: 7 } };
  db.prepare('INSERT INTO oauth_flows VALUES (?,?,?,?)').run(digest(flowToken), digest(sessionToken), vault.seal(flow, `oauth:${digest(sessionToken)}:${digest(flowToken)}`), until);
  db.prepare('INSERT INTO invocations VALUES (?,?,?,?,?,?,?,?,?)').run('old-run', USER_A, keyId, 'Existing AI', 'http.request', 'GET example.test', 'ok', 'HTTP 200', stamp);
  db.close();
  return { path, token, sessionToken, flowToken, keyId, connectionId, entries, ids, state, stamp };
}

test('稼働中の形式から保存値・接続・所有者・認証セッションを維持して移行する', async t => {
  const old = await previous(t), store = new Store(old.path, KEY); t.after(() => store.close());
  const { secrets, connections, principals, sessions, flows } = resources(store);
  for (const entry of old.entries) {
    const row = secrets.at(entry.owner, entry.name);
    assert.equal(row.id, entry.id); assert.equal(row.content, entry.ciphertext); assert.equal(row.readable, entry.readable);
    assert.equal(row.created_at, old.stamp); assert.equal(row.updated_at, old.stamp);
    assert.deepEqual(secrets.content(row), entry.content);
  }
  const row = connections.get(USER_A, old.connectionId);
  assert.equal(row.generation, 7); assert.equal(row.connector, 'gmail.readonly'); assert.equal(row.status, 'connected');
  assert.deepEqual(connections.state(row), old.state);
  assert.deepEqual({ ...store.db.prepare('SELECT principal_id,last_used_at FROM credentials WHERE hash=?').get(digest(old.token)) }, { principal_id: old.keyId, last_used_at: old.stamp });
  assert.equal(principals.actsFor(old.keyId)[0].id, USER_A);
  assert.equal(sessions.get(old.sessionToken).owner_id, USER_A);
  const flow = flows.take(digest(old.sessionToken), old.flowToken);
  assert.equal(flow.connector, 'gmail.readonly'); assert.equal(flow.requestId, old.ids.pending);
  assert.deepEqual(flow.previous, { id: old.connectionId, generation: 7 });
  assert.equal(store.db.prepare("SELECT value FROM metadata WHERE name='wrapped_key'").get().value, 'fixture-encrypted-envelope');
});

test('移行後の依頼で完了結果を返し、失効済みキーの未完了依頼を取り消す', async t => {
  const old = await previous(t), f = await fixture(t, { database: old.path, login: false });
  const headers = { cookie: 'fdn_session=' + old.sessionToken };
  for (const name of ['connect', 'revokedDone']) {
    const answer = await f.request('/v1/requests/' + old.ids[name], { headers });
    assert.equal(answer.json.request.status, 'done');
    assert.deepEqual(answer.json.request.result, { connection_id: old.connectionId });
  }
  const stored = (await f.request('/v1/requests/' + old.ids.store, { token: old.token })).json.request;
  assert.equal(stored.kind, 'store'); assert.deepEqual(stored.result, { names: ['with, comma'] });
  const cancelled = (await f.request('/v1/requests/' + old.ids.revoked, { headers })).json.request;
  assert.equal(cancelled.status, 'cancelled'); assert.equal(cancelled.reason, 'requester_revoked');
  const approval = (await f.request('/v1/requests/' + old.ids.approval, { headers })).json.request;
  assert.equal(approval.kind, 'actor'); assert.equal(approval.status, 'done'); assert.deepEqual(approval.result, { principal_id: old.keyId });
  const callback = await f.request('/oauth/gmail.readonly/callback?state=' + old.flowToken + '&code=personal-readonly', { headers });
  assert.match(callback.headers.get('location'), /connection=connected/);
  const completed = (await f.request('/v1/requests/' + old.ids.pending, { token: old.token })).json.request;
  assert.equal(completed.status, 'done'); assert.deepEqual(completed.result, { connection_id: old.connectionId });
  const delivered = await f.deliver({ id: old.connectionId }, { token: old.token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.delivery.environment.GOOGLE_OAUTH_ACCESS_TOKEN, old.state.private_state.access_token);
});

test('移行が失敗した場合は元のデータベースを維持し、正しい鍵で再試行する', async t => {
  const old = await previous(t);
  assert.throws(() => new Store(old.path, Buffer.alloc(32, 99)));
  const unchanged = new DatabaseSync(old.path, { readOnly: true });
  assert.equal(unchanged.prepare('PRAGMA user_version').get().user_version, 15);
  for (const entry of old.entries) assert.equal(unchanged.prepare('SELECT content FROM secrets WHERE id=?').get(entry.id).content, entry.ciphertext);
  unchanged.close();
  const store = new Store(old.path, KEY); t.after(() => store.close());
  const { connections } = resources(store);
  assert.deepEqual(connections.state(connections.get(USER_A, old.connectionId)), old.state);
});
