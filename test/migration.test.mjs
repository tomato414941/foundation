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
const SCHEMA_30 = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE access_keys (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, last_used_at TEXT, expires_at INTEGER, environment_id TEXT
  );
  CREATE INDEX access_keys_principal ON access_keys(principal_id);
  CREATE TABLE request_links (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
  );
  CREATE INDEX request_links_principal ON request_links(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
    alias TEXT, scope TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
  );
  CREATE INDEX relations_object ON relations(object_type, object_id, relation);
  CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
  CREATE TABLE permissions (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, action TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
    granted_by TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, action, object_type, object_id)
  );
  CREATE INDEX permissions_object ON permissions(object_type, object_id);
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
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('credential','object','app','service','environment')), name TEXT NOT NULL,
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
  -- A machine lent to a holder: what it is, how long it lives, who it acts as inside (if anyone), and where it runs.
  CREATE TABLE environments (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
    identity TEXT, runner TEXT NOT NULL, machine TEXT,
    status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopped')),
    started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE TABLE environment_commands (
    id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, by_id TEXT NOT NULL,
    command TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('running','done','timed_out','failed')),
    exit_code INTEGER, stdout TEXT, stderr TEXT, started_at INTEGER NOT NULL, ended_at INTEGER
  );
  CREATE INDEX environment_commands_environment ON environment_commands(environment_id, started_at);
  -- Computing is spent, not lent: what each principal used in a month, and the most its owner lets it use.
  CREATE TABLE compute_usage (principal_id TEXT NOT NULL, month TEXT NOT NULL, seconds INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (principal_id, month));
  CREATE TABLE compute_limits (principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, monthly_seconds INTEGER NOT NULL);
  CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX audit_log_actor ON audit_log(actor_id, at);
  CREATE INDEX audit_log_object ON audit_log(object_type, object_id, at);
  PRAGMA user_version = 30;
`;

test('30版のデータベースを、関係も渡した権限も一つの関係の記録に移し、何も失わない', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(SCHEMA_30);
  const stamp = '2026-01-01T00:00:00.000Z', key = 'fdn_' + 'k'.repeat(43), ai = '10000000-0000-4000-8000-00000000000a';
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  db.prepare('INSERT INTO principals VALUES (?,?,?)').run(USER_A, 'someone', stamp);
  db.prepare('INSERT INTO principals VALUES (?,?,?)').run(ai, 'ai', stamp);
  db.prepare('INSERT INTO access_keys (id,hash,principal_id,created_at) VALUES (?,?,?,?)').run('key-1', digest(key), ai, stamp);
  db.prepare("INSERT INTO resources (id,holder_id,kind,name,created_at,updated_at) VALUES ('object-1',?,'object','report.pdf',?,?)").run(USER_A, stamp, stamp);
  db.prepare("INSERT INTO objects (resource_id,size,type) VALUES ('object-1',14,'application/pdf')").run();
  db.prepare("INSERT INTO relations (subject_id,relation,object_type,object_id,alias,scope,created_at) VALUES (?,'owner','principal',?,'laptop','ignored',?)").run(USER_A, ai, stamp);
  db.prepare("INSERT INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,'actor','principal',?,?)").run(ai, USER_A, stamp);
  db.prepare("INSERT INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,'viewer','resource','object-1',?)").run(ai, stamp);
  db.prepare("INSERT INTO permissions (subject_id,action,object_type,object_id,granted_by,created_at) VALUES (?,'object.remove','resource','object-1',?,?)").run(ai, USER_A, stamp);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 31);
  const lines = store.db.prepare('SELECT subject_id,relation,object_type,object_id,alias FROM relations ORDER BY relation').all().map(row => ({ ...row }));
  assert.deepEqual(lines.map(row => row.relation), ['actor', 'object.remove', 'owner', 'viewer']);
  assert.equal(lines.find(row => row.relation === 'owner').alias, 'laptop', 'the name an owner gave stays');
  assert.equal(store.db.prepare("SELECT count(*) n FROM sqlite_schema WHERE name='permissions'").get().n, 0);
  assert.deepEqual(new Principals(store).authenticateKey(key)?.key, { id: 'key-1' });
  assert.equal(store.db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1, 'references are checked again after the step');
  store.db.prepare(`DELETE FROM principals WHERE id='${ai}'`).run();
  assert.equal(store.db.prepare('SELECT count(*) n FROM relations WHERE subject_id=?').get(ai).n, 0, 'and still follow what they refer to');
});

test('もう誰も動かしていない形のデータベースは、移行せずに断る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE secrets (id TEXT); PRAGMA user_version = 25;');
  db.close();
  assert.throws(() => new Store(path, KEY), /not created by this version/);
});
