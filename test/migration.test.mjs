import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault, digest } from '../src/crypto.mjs';
import { Principals } from '../src/principals.mjs';
import { KEY, USER_A } from './helpers.mjs';

// The schema a running Foundation is on today, fixed here so the step is tested against what it will meet.
const SCHEMA_27 = `

  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE access_keys (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE INDEX access_keys_principal ON access_keys(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
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
    kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect','app')), input TEXT NOT NULL,
    purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  -- What a holder holds: one row each, and a row in the table of its kind.
  CREATE TABLE resources (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('credential','object','app','service')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX resources_holder ON resources(holder_id, kind, name);
  CREATE UNIQUE INDEX resources_object_name ON resources(holder_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX resources_app_name ON resources(holder_id, name) WHERE kind='app';
  CREATE UNIQUE INDEX resources_service_name ON resources(holder_id, name) WHERE kind='service';
  -- A credential for a service (by the scheme it came by), or a secret (no service).
  CREATE TABLE credentials (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT, auth_scheme TEXT CHECK(auth_scheme IN ('oauth','token','role')),
    app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB,
    CHECK((service IS NULL) = (auth_scheme IS NULL))
  );
  CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;
  CREATE TABLE objects (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  -- An OAuth app someone holds: which service it is for, its client ID, what else is said of it, and its sealed secret.
  CREATE TABLE apps (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL, settings TEXT NOT NULL DEFAULT '{}'
  );
  -- A service a holder described, for one Foundation's catalog does not know.
  CREATE TABLE services (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, definition TEXT NOT NULL);
  CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX audit_log_actor ON audit_log(actor_id, at);
  CREATE INDEX audit_log_object ON audit_log(object_type, object_id, at);
  PRAGMA user_version = 27;
`;

test('27版のデータベースから、アクセスキーはそのまま使え、依頼のリンクは依頼リンクとして開ける', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(SCHEMA_27);
  const stamp = '2026-01-01T00:00:00.000Z', key = 'fdn_' + 'k'.repeat(43), link = 'l'.repeat(43), requestId = 'r'.repeat(43);
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  db.prepare('INSERT INTO principals VALUES (?,?,?)').run(USER_A, 'someone', stamp);
  db.prepare("INSERT INTO access_keys (id,hash,principal_id,kind,scope,expires_at,created_at,last_used_at) VALUES ('key-1',?,?,'key',NULL,NULL,?,?)").run(digest(key), USER_A, stamp, stamp);
  db.prepare("INSERT INTO access_keys (id,hash,principal_id,kind,scope,expires_at,created_at) VALUES ('link-1',?,?,'link',?,?,?)").run(digest(link), USER_A, 'request:' + requestId, Date.now() + 600_000, stamp);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 28);
  const principals = new Principals(store);
  assert.deepEqual(principals.authenticateKey(key)?.key, { id: 'key-1' });
  assert.deepEqual(principals.keys(USER_A).map(row => row.id), ['key-1']);
  assert.deepEqual(principals.authenticateLink(link, requestId)?.link, { id: 'link-1', request: requestId });
  assert.equal(principals.authenticateKey(link), undefined);
});

test('もう誰も動かしていない形のデータベースは、移行せずに断る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE secrets (id TEXT); PRAGMA user_version = 25;');
  db.close();
  assert.throws(() => new Store(path, KEY), /not created by this version/);
});
