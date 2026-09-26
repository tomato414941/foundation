import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault } from '../src/crypto.mjs';
import { resources, KEY, USER_A } from './helpers.mjs';

// The schema a running Foundation is on today, fixed here so the step is tested against what it will meet.
const SCHEMA_20 = `

  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE credentials (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE INDEX credentials_principal ON credentials(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','holding')), object_id TEXT NOT NULL,
    alias TEXT, scope TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
  );
  CREATE INDEX relations_object ON relations(object_type, object_id, relation);
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
  CREATE TABLE holdings (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','object','connection')), name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0, type TEXT, content BLOB,
    connector TEXT, subject TEXT, status TEXT, generation INTEGER NOT NULL DEFAULT 1, kept_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
  CREATE UNIQUE INDEX holdings_name ON holdings(holder_id, kind, name) WHERE kind <> 'connection';
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = 20;
`;

test('今日動いている形からの移行は、持ち物と接続をそのまま保ち、誰が作ったかの列だけを落とす', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(SCHEMA_20);
  const stamp = '2026-01-01T00:00:00.000Z';
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  db.prepare('INSERT INTO principals VALUES (?,?,?)').run(USER_A, '', stamp);
  const content = Buffer.from('kept-bytes');
  db.prepare("INSERT INTO holdings (id,holder_id,kind,name,size,content,created_at,updated_at) VALUES ('secret-1',?,'secret','doc',?,?,?,?)").run(USER_A, content.length, vault.sealBytes(content, `entry:${USER_A}:secret-1`), stamp, stamp);
  const state = { private_state: { token: 'x' }, facts: { label: 'me@example.test' }, expires_at: null };
  db.prepare("INSERT INTO holdings (id,holder_id,kind,name,content,connector,subject,status,generation,kept_by,created_at,updated_at) VALUES ('connection-1',?,'connection','me@example.test',?,'gmail.readonly','me@example.test','connected',3,'dev',?,?)").run(USER_A, vault.seal(state, `connection:${USER_A}:connection-1`), stamp, stamp);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 21);
  const { secrets, connections } = resources(store);
  assert.deepEqual(secrets.content(secrets.find(USER_A, 'doc')), content);
  const connection = connections.get(USER_A, 'connection-1');
  assert.equal(connection.generation, 3); assert.deepEqual(connections.state(connection), state);
  assert.equal(store.db.prepare("SELECT count(*) n FROM pragma_table_info('holdings') WHERE name='kept_by'").get().n, 0);
});

test('もう誰も動かしていない形の データベースは、移行せずに断る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE secrets (id TEXT); PRAGMA user_version = 18;');
  db.close();
  assert.throws(() => new Store(path, KEY), /not created by this version/);
});
