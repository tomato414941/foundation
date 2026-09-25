import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault, digest } from '../src/crypto.mjs';
import { READONLY_SCOPE } from '../src/connectors/gmail/client.mjs';
import { FakeAuth, fixture, resources, KEY, USER_A, USER_B } from './helpers.mjs';

// Schema 11, fixed independently of the current schema so the migration test cannot
// accidentally create only the new shape. All credentials below are test fixtures.
const LEGACY_SCHEMA = `
  CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE keys (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, last_used_at TEXT, issued_until INTEGER, issued_nonexpiring INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE key_requests (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, name TEXT NOT NULL, confirmation_code TEXT NOT NULL,
    confirmation_attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, owner_id TEXT, key_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
  CREATE INDEX key_requests_token ON key_requests(token_hash, created_at);
  CREATE TABLE requests (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, key_id TEXT NOT NULL, owner_id TEXT NOT NULL, requester_name TEXT NOT NULL,
    adapter TEXT, purpose TEXT NOT NULL, details TEXT NOT NULL, steps TEXT NOT NULL, progress TEXT, credential_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
  CREATE INDEX requests_token ON requests(token_hash, created_at);
  CREATE TABLE secrets (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
    readable INTEGER NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(owner_id,path));
  CREATE TABLE acquisitions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, prefix TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL,
    label TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
    kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(owner_id,prefix), UNIQUE(owner_id,adapter,subject));
  CREATE INDEX acquisitions_owner ON acquisitions(owner_id,prefix);
  CREATE INDEX secrets_owner ON secrets(owner_id,path);
  PRAGMA user_version=11;
`;

async function legacy(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(LEGACY_SCHEMA);
  const stamp = '2026-01-01T00:00:00.000Z', expires = Date.now() + 600_000;
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  const token = 'fdn_' + 'k'.repeat(43), keyId = 'legacy-key', sessionToken = 'b'.repeat(43), sessionId = digest(sessionToken);
  db.prepare('INSERT INTO keys (id,owner_id,name,token_hash,created_at,issued_until,issued_nonexpiring) VALUES (?,?,?,?,?,?,?)')
    .run(keyId, USER_A, 'Existing key', digest(token), stamp, expires, 1);
  const auth = new FakeAuth().value();
  db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)').run(sessionId, USER_A, auth.user.email, vault.seal(auth, `session:${sessionId}`), expires);
  const savedNames = ['gmail/personal-example-test/google-oauth-access-token', 'gmail/personal-example-test/custom', 'ordinary'];
  const entries = [];
  for (const owner of [USER_A, USER_B]) for (const [index, name] of savedNames.entries()) {
    const id = owner + ':' + index, content = Buffer.from([0, 255, index, owner === USER_A ? 1 : 2]);
    const sealed = vault.sealBytes(content, `entry:${owner}:${id}`);
    db.prepare('INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?)').run(id, owner, name, content.length, index % 2, sealed, stamp, stamp);
    entries.push({ owner, id, name, content, sealed });
  }
  const state = { renewal: { access_token: 'google-access-personal-readonly', refresh_token: 'refresh-personal-readonly', scopes: [READONLY_SCOPE], expires_at: expires }, facts: {}, expires_at: expires };
  const prefix = 'gmail/personal-example-test', connectionId = 'legacy-connection', encryptedState = vault.seal(state, `acquisition:${USER_A}:${connectionId}`);
  db.prepare('INSERT INTO acquisitions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(connectionId, USER_A, prefix, 'gmail.readonly', 'personal@example.test', 'Personal', encryptedState, 'connected', 4, 'existing', stamp, stamp);
  const requestIds = { pending: 's'.repeat(43), saved: 'd'.repeat(43), connected: 'c'.repeat(43), connecting: 'p'.repeat(43) };
  for (const [kind, id] of Object.entries(requestIds)) {
    const connect = ['connected', 'connecting'].includes(kind), done = ['saved', 'connected'].includes(kind);
    const details = connect ? [] : [{ path: 'ordinary', label: '値', secret: true, site: '', multiline: false }];
    db.prepare('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, digest(token), keyId, USER_A, 'Existing key',
      connect ? 'gmail.readonly' : null, '既存の依頼', JSON.stringify(details), '["入力してください"]', '[{"event":"page_viewed","at":1}]',
      done ? connect ? prefix : 'ordinary' : null, done ? 'done' : 'pending', Date.now(), expires);
  }
  const flowState = 'f'.repeat(43), flowId = digest(flowState);
  const flow = { adapter: 'gmail.readonly', requestedBy: 'existing', verifier: 'test-verifier', redirectUri: 'https://example.test/oauth/gmail.readonly/callback',
    requestId: requestIds.connecting, previous: { prefix, generation: 4 } };
  db.prepare('INSERT INTO oauth_flows VALUES (?,?,?,?)').run(flowId, sessionId, vault.seal(flow, `oauth:${sessionId}:${flowId}`), expires);
  db.prepare('INSERT INTO key_requests (id,token_hash,name,confirmation_code,created_at,expires_at) VALUES (?,?,?,?,?,?)')
    .run('q'.repeat(43), digest('fdn_' + 'q'.repeat(43)), 'Pending key', digest('1234-ABCD'), Date.now(), expires);
  db.close();
  return { path, entries, state, encryptedState, connectionId, token, sessionToken, sessionId, flowState, requestIds, stamp };
}

test('Schema 11 migrates encrypted values and pending state without changing their identities or contents', async t => {
  const old = await legacy(t), store = new Store(old.path, KEY); t.after(() => store.close());
  const { secrets, connections, principals, sessions, flows } = resources(store);
  const fresh = new Store(':memory:', KEY), current = fresh.db.prepare('PRAGMA user_version').get().user_version; fresh.close();
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, current, 'carried to the shape a new database has');
  for (const entry of old.entries) {
    const row = secrets.find(entry.owner, entry.name);
    assert.equal(row.id, entry.id); assert.equal(row.content, entry.sealed);
    assert.equal(row.created_at, old.stamp); assert.equal(row.updated_at, old.stamp);
    assert.deepEqual(secrets.content(row), entry.content);
  }
  const connection = connections.get(USER_A, old.connectionId);
  assert.equal(connection.generation, 4);
  assert.deepEqual(connections.state(connection), { private_state: old.state.renewal, facts: old.state.facts, expires_at: old.state.expires_at });
  assert.equal(principals.actsFor('legacy-key')[0].id, USER_A);
  assert.equal(sessions.get(old.sessionToken).id, old.sessionId);
  assert.equal(principals.actorsOf(USER_A)[0].name, 'Existing key');
  // Everyone the old database knew is a principal now: the key, and each person by the id their login gave them.
  assert.deepEqual({ ...store.db.prepare('SELECT id,name,created_at FROM principals WHERE id=?').get('legacy-key') }, { id: 'legacy-key', name: 'Existing key', created_at: old.stamp });
  assert.deepEqual(store.db.prepare('SELECT id FROM principals WHERE id IN (?,?) ORDER BY id').all(USER_A, USER_B).map(row => row.id), [USER_A, USER_B].sort());
  assert.deepEqual({ ...store.db.prepare('SELECT principal_id,kind FROM credentials WHERE hash=?').get(digest(old.token)) }, { principal_id: 'legacy-key', kind: 'key' });
  assert.equal(store.db.prepare("SELECT count(*) n FROM requests WHERE kind='actor'").get().n, 1);
  const flow = flows.take(old.sessionId, old.flowState);
  assert.deepEqual(flow.previous, { id: old.connectionId, generation: 4 });
  assert.equal(flow.requestId, old.requestIds.connecting);
  assert.equal(flow.connector, 'gmail.readonly');
  connections.disconnect(USER_A, connection.id); connections.remove(USER_A, connection.id);
  for (const entry of old.entries) assert.deepEqual(secrets.content(secrets.find(entry.owner, entry.name)), entry.content);
});

test('Migrated pending requests and OAuth callbacks complete through the current API', async t => {
  const old = await legacy(t), f = await fixture(t, { database: old.path, login: false });
  const headers = { cookie: 'fdn_session=' + old.sessionToken };
  const pending = await f.request('/v1/requests/' + old.requestIds.pending, { token: old.token });
  assert.equal(pending.json.request.status, 'pending');
  assert.equal(pending.json.request.store[0].name, 'ordinary');
  assert.deepEqual(pending.json.request.steps, ['入力してください']);
  assert.equal(pending.json.request.events[0].event, 'page_viewed');
  assert.deepEqual((await f.request('/v1/requests/' + old.requestIds.saved, { token: old.token })).json.request.result, { names: ['ordinary'] });
  assert.equal((await f.request('/v1/requests/' + old.requestIds.connected, { token: old.token })).json.request.result.connection_id, old.connectionId);
  const complete = await f.request('/v1/requests/' + old.requestIds.pending + '/done', { method: 'POST', headers, data: { entries: [{ name: 'new ordinary', content: 'new ordinary value' }] } });
  assert.equal(complete.status, 200, complete.text);
  assert.equal(f.app.secrets.content(f.app.secrets.find(USER_A, 'new ordinary')).toString(), 'new ordinary value');
  const callback = await f.request('/oauth/gmail.readonly/callback?state=' + old.flowState + '&code=personal-readonly', { headers });
  assert.equal(callback.headers.get('location'), '/requests/' + old.requestIds.connecting + '?connection=connected');
  assert.equal(f.app.connections.get(USER_A, old.connectionId).generation, 5);
  assert.equal((await f.request('/v1/requests/' + old.requestIds.connecting, { token: old.token })).json.request.result.connection_id, old.connectionId);
  for (const entry of old.entries) assert.deepEqual(f.app.secrets.content(f.app.secrets.find(entry.owner, entry.name)), entry.content);
});

test('Wrong encryption key rolls the entire schema migration back; the original key still opens it', async t => {
  const old = await legacy(t);
  assert.throws(() => new Store(old.path, Buffer.alloc(32, 99)));
  const before = new DatabaseSync(old.path);
  assert.equal(before.prepare('PRAGMA user_version').get().user_version, 11);
  for (const entry of old.entries) assert.equal(before.prepare('SELECT content FROM secrets WHERE owner_id=? AND path=?').get(entry.owner, entry.name).content, entry.sealed);
  before.close();
  const opened = new Store(old.path, KEY);
  const { connections } = resources(opened);
  assert.deepEqual(connections.state(connections.get(USER_A, old.connectionId)).private_state, old.state.renewal);
  opened.close();
});
