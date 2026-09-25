import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault } from '../src/crypto.mjs';
import { resources, KEY, USER_A, USER_B } from './helpers.mjs';

// Schema 18, fixed here so the migration test cannot accidentally create only the new shape.
const SCHEMA_18 = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE credentials (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE INDEX credentials_principal ON credentials(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','secret','object','connection')), holder_id TEXT NOT NULL DEFAULT '', object_id TEXT NOT NULL,
    alias TEXT, scope TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, holder_id, object_id)
  );
  CREATE INDEX relations_object ON relations(object_type, holder_id, object_id, relation);
  CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
  CREATE TABLE settings (
    principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    return_url TEXT NOT NULL, refresh_url TEXT, webhook_url TEXT, webhook_secret TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE requests (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect')), input TEXT NOT NULL,
    purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  CREATE TABLE secrets (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
    size INTEGER NOT NULL, readable INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, name)
  );
  CREATE INDEX secrets_owner ON secrets(owner_id, name);
  CREATE TABLE connections (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, connector TEXT NOT NULL, subject TEXT NOT NULL,
    label TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
    kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, connector, subject)
  );
  CREATE INDEX connections_owner ON connections(owner_id, id);
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = 18;
`;

test('スキーマ 19 は保管物を一つの表にまとめ、線は名前ではなく ID を指すようになる', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(SCHEMA_18);
  const stamp = '2026-01-01T00:00:00.000Z';
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  for (const id of [USER_A, USER_B, 'reader']) db.prepare('INSERT INTO principals VALUES (?,?,?)').run(id, id, stamp);
  const content = Buffer.from('kept-bytes'), secretId = 'secret-1';
  db.prepare('INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?)').run(secretId, USER_A, 'doc', content.length, 1, vault.sealBytes(content, `entry:${USER_A}:${secretId}`), stamp, stamp);
  db.prepare('INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?)').run('secret-2', USER_B, 'doc', content.length, 1, vault.sealBytes(content, `entry:${USER_B}:secret-2`), stamp, stamp);
  const state = { private_state: { token: 'x' }, facts: { label: 'me@example.test' }, expires_at: null }, connectionId = 'connection-1';
  db.prepare("INSERT INTO connections VALUES (?,?,?,?,?,?,'connected',3,?,?,?)").run(connectionId, USER_A, 'gmail.readonly', 'me@example.test', 'me@example.test', vault.seal(state, `connection:${USER_A}:${connectionId}`), 'dev', stamp, stamp);
  db.prepare("INSERT INTO relations VALUES (?,?,?,?,?,?,?,?)").run(USER_A, 'owner', 'principal', '', 'reader', null, null, stamp);
  db.prepare("INSERT INTO relations VALUES (?,?,?,?,?,?,?,?)").run('reader', 'viewer', 'secret', USER_A, 'doc', null, null, stamp);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 19);
  const { secrets, principals, connections } = resources(store);
  const kept = secrets.find(USER_A, 'doc');
  assert.equal(kept.id, secretId, 'the thing keeps its id');
  assert.deepEqual(secrets.content(kept), content, 'and its bytes still open');
  assert.equal(secrets.find(USER_B, 'doc').id, 'secret-2');
  const connection = connections.get(USER_A, connectionId);
  assert.equal(connection.generation, 3);
  assert.deepEqual(connections.state(connection), state);
  assert.deepEqual(principals.shownTo('reader').map(row => [row.id, row.relation]), [[secretId, 'viewer']], 'the line now points at the id of the one thing it was drawn onto');
  assert.ok(principals.has(USER_A, 'owner', 'principal', 'reader'));
  assert.equal(store.db.prepare("SELECT count(*) n FROM sqlite_master WHERE name IN ('secrets','connections')").get().n, 0);
});
