import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault, digest } from '../src/crypto.mjs';
import { Principals } from '../src/principals.mjs';
import { SCHEMA_VERSION, STEPS } from '../src/migrations.mjs';
import { OAuth2Client, inject } from '../src/schemes/oauth.mjs';
import { Authorization } from '../src/authorization.mjs';
import { KEY, USER_A, USER_B, modules } from './helpers.mjs';

const STORED_SERVICE = { version: 1, name: 'Stored service', auth_schemes: { oauth: {
  authorize: 'https://service.example/authorize', token: 'https://service.example/token', keep: ['id'], ok_field: 'ok',
  identity: { url: '{id}', id: ['data.viewer.id', 'organization_id'], label: ['data.viewer.email'] },
  injection: { ACCESS_TOKEN: '{access_token}', ACCOUNT: '{account}', EXPIRES_AT: '{expires_at}' },
} } };

// A connection's state is sealed under its name, so it is compared by what it opens to instead.
const SNAPSHOT_COLUMNS = { credentials: 'resource_id,service,auth_scheme,app_id,subject,status,generation' };

async function storedDefinitions(t, definitions) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-reference-migration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), m = modules(store);
  const secret = m.secrets.put(USER_A, { name: 'token#work', content: Buffer.from([0, 255, 10, 42]) });
  const ids = definitions.map((definition, i) => {
    const id = '12345678-1234-4234-8234-' + String(i + 1).padStart(12, '0');
    m.resources.insert(id, USER_A, 'service', 'Service ' + i);
    store.db.prepare('INSERT INTO services VALUES (?,?)').run(id, JSON.stringify(definition));
    return id;
  });
  const credential = m.connections.keep(USER_A, { service: ids[0], scheme: 'oauth', subject: 'account', label: 'Account',
    state: { private_state: { refresh_token: 'kept-refresh' }, facts: {}, expires_at: null } });
  // Back to the shape of schema 34: connections were credentials then, sealed under that name.
  const vault = new Vault(KEY);
  for (const row of store.db.prepare('SELECT c.resource_id, c.state, r.holder_id FROM connections c JOIN resources r ON r.id=c.resource_id').all()) {
    store.db.prepare('UPDATE connections SET state=? WHERE resource_id=?').run(vault.seal(vault.open(row.state, `connection:${row.holder_id}:${row.resource_id}`), `credential:${row.holder_id}:${row.resource_id}`), row.resource_id);
  }
  store.db.exec('DROP INDEX connections_app; ALTER TABLE connections RENAME TO credentials; CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;');
  store.db.exec(`DROP TABLE emails; DROP TABLE challenges; DROP TABLE oauth_flows; DROP TABLE sessions;
    CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);`);
  const snapshots = Object.fromEntries(['resources', 'secrets', 'credentials', 'relations'].map(table => [table, store.db.prepare(`SELECT ${SNAPSHOT_COLUMNS[table] ?? '*'} FROM ${table}`).all()]));
  store.db.exec('PRAGMA user_version=34'); store.close();
  return { path, ids, secret, credential, snapshots };
}

test('保存済みのサービス定義を標準参照に変換し、値・ID・名前・接続状態・権限を保持する', async t => {
  const old = await storedDefinitions(t, [STORED_SERVICE, { version: 1, name: 'Empty service' }]);
  const store = new Store(old.path, KEY);
  for (const [table, expected] of Object.entries(old.snapshots)) {
    const now = table === 'credentials' ? 'connections' : table;
    assert.deepEqual(store.db.prepare(`SELECT ${SNAPSHOT_COLUMNS[table] ?? '*'} FROM ${now}`).all(), expected, table);
  }
  const definition = JSON.parse(store.db.prepare('SELECT definition FROM services WHERE resource_id=?').get(old.ids[0]).definition);
  const oauth = definition.auth_schemes.oauth;
  assert.deepEqual(definition, { name: 'Stored service', auth_schemes: { oauth: {
    authorize: 'https://service.example/authorize', token: 'https://service.example/token', keep: ['id'], ok_field: '/ok',
    identity: { url: '{+id}', id: ['/data/viewer/id', '/organization_id'], label: ['/data/viewer/email'] },
    injection: { ACCESS_TOKEN: '/access_token', ACCOUNT: '/account', EXPIRES_AT: '/expires_at' },
  } } });
  assert.deepEqual(inject(oauth.injection, { access_token: 'active', account: 'viewer:organization', expires_at: null }), { ACCESS_TOKEN: 'active', ACCOUNT: 'viewer:organization' });
  const client = new OAuth2Client({ clientId: 'id', clientSecret: 'secret' }, { profile: oauth });
  assert.equal(client.expand(oauth.identity.url, { id: 'https://service.example/a%2Fb' }), 'https://service.example/a%2Fb');
  assert.equal(client.pick({ data: { viewer: { id: 'viewer', email: 'mail@example.test' } }, organization_id: 'organization' }, oauth.identity).id, 'viewer:organization');
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  const text = store.db.prepare('SELECT definition FROM services ORDER BY resource_id').all();
  store.close();
  const reopened = new Store(old.path, KEY); t.after(() => reopened.close());
  assert.deepEqual(reopened.db.prepare('SELECT definition FROM services ORDER BY resource_id').all(), text);
  const m = modules(reopened);
  assert.deepEqual(m.secrets.content(m.secrets.get(old.secret.id)), Buffer.from([0, 255, 10, 42]));
  assert.equal(m.connections.state(m.connections.get(old.credential.id)).private_state.refresh_token, 'kept-refresh');
});

test('安全に変換できないサービス定義があれば、移行全体を取り消して元のデータを保持する', async t => {
  const composite = structuredClone(STORED_SERVICE);
  composite.auth_schemes.oauth.injection.ACCESS_TOKEN = 'Bearer {access_token}';
  const old = await storedDefinitions(t, [STORED_SERVICE, composite]);
  assert.throws(() => new Store(old.path, KEY), /could not be migrated/);
  const db = new DatabaseSync(old.path); t.after(() => db.close());
  assert.equal(db.prepare('PRAGMA user_version').get().user_version, 34);
  assert.deepEqual(db.prepare('SELECT definition FROM services ORDER BY resource_id').all().map(row => JSON.parse(row.definition)), [STORED_SERVICE, composite]);
  for (const [table, expected] of Object.entries(old.snapshots)) assert.deepEqual(db.prepare(`SELECT ${SNAPSHOT_COLUMNS[table] ?? '*'} FROM ${table}`).all(), expected, table);
});

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

test('30版のデータベースを、関係も渡した権限も一つの関係の記録に移し、呼び名は所有者の記録として分け、何も失わない', async t => {
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
  db.prepare("INSERT INTO permissions (subject_id,action,object_type,object_id,granted_by,created_at) VALUES (?,'export.read','principal',?,?,?)").run(ai, USER_A, USER_A, stamp);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  const lines = store.db.prepare('SELECT * FROM relations ORDER BY relation').all().map(row => ({ ...row }));
  assert.deepEqual(lines.map(row => row.relation), ['actor', 'object.remove', 'owner', 'principal.export', 'viewer'], 'what was done to a principal as a whole is its own action');
  assert.deepEqual(Object.keys(lines[0]).sort(), ['created_at', 'object_id', 'object_type', 'relation', 'subject_id'], 'a line is who, which, onto what');
  assert.equal(new Principals(store).aliasOf(USER_A, ai), 'laptop', 'the name an owner gave stays, as the owner\'s record');
  assert.equal(store.db.prepare("SELECT count(*) n FROM sqlite_schema WHERE name='permissions'").get().n, 0);
  assert.deepEqual(new Principals(store).authenticateKey(key)?.key, { id: 'key-1' });
  assert.equal(store.db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1, 'references are checked again after the step');
  store.db.prepare(`DELETE FROM principals WHERE id='${ai}'`).run();
  assert.equal(store.db.prepare('SELECT count(*) n FROM relations WHERE subject_id=?').get(ai).n, 0, 'and still follow what they refer to');
});

async function previous(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migrate-secrets-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY);
  db.exec(SCHEMA_30);
  STEPS[31]({ db }); db.exec('PRAGMA user_version=31');
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('key_check', vault.seal(true, 'key_check'));
  const stamp = '2026-01-01T00:00:00.000Z', reader = 'reader';
  for (const id of [USER_A, reader]) db.prepare('INSERT INTO principals VALUES (?,?,?)').run(id, id, stamp);
  const resource = (id, kind, name) => db.prepare('INSERT INTO resources VALUES (?,?,?,?,?,?)').run(id, USER_A, kind, name, stamp, stamp);
  const keep = (id, name, scheme, value) => {
    resource(id, 'credential', name);
    const state = scheme ? vault.seal(value, 'credential:' + USER_A + ':' + id) : vault.sealBytes(value, 'credential:' + USER_A + ':' + id);
    db.prepare('INSERT INTO credentials (resource_id,service,auth_scheme,subject,generation,size,state) VALUES (?,?,?,?,?,?,?)')
      .run(id, scheme ? '12345678-1234-4234-8234-123456789012' : null, scheme, scheme ? 'account-one' : null, 7, scheme ? 0 : value.length, state);
  };
  const line = (relation, type, id) => db.prepare('INSERT INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,?,?,?,?)').run(reader, relation, type, id, stamp);
  return { db, vault, path, reader, resource, keep, line };
}

test('31版のシークレットと固定トークンを値・ID・共有権限を保って移し、OAuthとロールの状態も保持する', async t => {
  const old = await previous(t), bytes = Buffer.from([0, 255, 10, 1]), fields = { token: 'private-token', account_id: 'account-one' };
  old.keep('plain', 'same name', null, bytes);
  old.keep('single', 'same name', 'token', { private_state: { fields: { token: 'single-token' } } });
  old.keep('multi', 'multiple values', 'token', { private_state: { fields } });
  const managed = { private_state: { refresh_token: 'refresh-private' }, facts: { label: 'account-one' }, expires_at: null };
  old.keep('oauth', 'OAuth account', 'oauth', managed);
  old.keep('role', 'AWS role', 'role', { ...managed, private_state: { role_arn: 'arn:aws:iam::123456789012:role/fixture' } });
  old.line('viewer', 'resource', 'plain');
  old.line('credential.write', 'resource', 'plain');
  old.line('viewer', 'resource', 'single');
  old.line('credential.content', 'resource', 'single');
  old.line('credential.disconnect', 'resource', 'single');
  old.line('credential.list', 'principal', USER_A);
  old.line('credential.rename', 'resource', 'oauth');
  old.resource('12345678-1234-4234-8234-123456789012', 'service', 'Notes');
  old.db.prepare('INSERT INTO services VALUES (?,?)').run('12345678-1234-4234-8234-123456789012', JSON.stringify({ version: 1, name: 'Notes',
    auth_schemes: { token: { fields: [{ name: 'token', label: 'Token', secret: true }], injection: { API_TOKEN: '{token}' } } },
  }));
  const expires = Date.now() + 3600000;
  for (const status of ['pending', 'done']) old.db.prepare('INSERT INTO requests (id,from_id,to_id,kind,input,purpose,steps,status,result,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .run('request-' + status, old.reader, USER_A, 'connect', JSON.stringify({ service: '12345678-1234-4234-8234-123456789012', auth_scheme: 'token' }), 'test', '[]', status,
      status === 'done' ? JSON.stringify({ credential_id: 'single' }) : null, Date.now(), expires);
  old.db.close();

  const store = new Store(old.path, KEY); t.after(() => store.close());
  const { secrets, connections, services, principals, authorization } = modules(store);
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual(secrets.content(secrets.get('plain')), bytes);
  assert.equal(secrets.get('plain').name, 'same name');
  assert.equal(secrets.get('plain').generation, 7);
  assert.equal(secrets.get('single').name, 'same name (single)');
  assert.equal(secrets.content(secrets.get('single')).toString(), 'single-token');
  assert.deepEqual(JSON.parse(secrets.content(secrets.get('multi')).toString()), fields);
  assert.deepEqual(connections.state(connections.get('oauth')), managed);
  assert.equal(connections.get('oauth').generation, 7);
  assert.equal(connections.state(connections.get('role')).private_state.role_arn, 'arn:aws:iam::123456789012:role/fixture');
  assert.equal(services.get('12345678-1234-4234-8234-123456789012').definition.name, 'Notes');
  const allowed = (action, id, type = 'secret') => authorization.can(old.reader, action, type, { holder: USER_A, id });
  assert.equal(allowed('content', 'plain'), true);
  assert.equal(allowed('write', 'plain'), true);
  assert.equal(allowed('read', 'single'), true);
  assert.equal(allowed('content', 'single'), false, 'a former metadata viewer still cannot read the private value');
  assert.equal(allowed('write', 'single'), false);
  assert.equal(allowed('remove', 'single'), true);
  assert.equal(allowed('rename', 'oauth', 'connection'), true);
  assert.equal(authorization.can(old.reader, 'list', 'secret', { holder: USER_A }), true);
  assert.equal(authorization.can(old.reader, 'list', 'connection', { holder: USER_A }), true);
  assert.equal(store.db.prepare("SELECT status FROM requests WHERE id='request-pending'").get().status, 'cancelled');
  assert.deepEqual(JSON.parse(store.db.prepare("SELECT result FROM requests WHERE id='request-done'").get().result), { connection_id: 'single' });
  assert.deepEqual({ ...store.db.prepare("SELECT type,status,user_code FROM requests WHERE id='request-done'").get() }, { type: 'connection', status: 'granted', user_code: null }, 'a request says what it asks as a detail, and is granted');
  assert.deepEqual(store.db.prepare('PRAGMA foreign_key_check').all(), []);
  assert.deepEqual(principals.shownTo(old.reader).filter(row => row.id === 'plain').map(row => row.kind), ['secret', 'secret']);
});

test('移行で値を復号できない場合は全体をロールバックして以前のデータを保持する', async t => {
  for (const corrupt of [false, true]) {
    const old = await previous(t);
    old.keep('plain', 'private value', null, Buffer.from('private-value'));
    old.keep('token', 'token', 'token', corrupt ? { private_state: {} } : { private_state: { fields: { token: 'token-private' } } });
    const before = old.db.prepare('SELECT * FROM credentials ORDER BY resource_id').all();
    old.db.close();
    assert.throws(() => new Store(old.path, corrupt ? KEY : Buffer.alloc(32, 8)));
    const check = new DatabaseSync(old.path);
    try {
      assert.equal(check.prepare('PRAGMA user_version').get().user_version, 31);
      assert.deepEqual(check.prepare('SELECT * FROM credentials ORDER BY resource_id').all(), before);
      assert.equal(check.prepare("SELECT kind FROM resources WHERE id='plain'").get().kind, 'credential');
    } finally { check.close(); }
  }
});

test('もう誰も動かしていない形のデータベースは、移行せずに断る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE secrets (id TEXT); PRAGMA user_version = 25;');
  db.close();
  assert.throws(() => new Store(path, KEY), /not created by this version/);
});

test('36版のセッションでサインインしていたアドレスは、その人の確かめたアドレスとして残り、古いセッションは終わる', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-37-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  const { principals } = modules(store);
  principals.ensure(USER_A); principals.ensure(USER_B);
  store.db.exec(`DROP TABLE emails; DROP TABLE challenges; DROP TABLE oauth_flows; DROP TABLE sessions;
    CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);`);
  const old = store.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)');
  old.run('a1', USER_A, 'Owner@Example.test', 'sealed', Date.now() + 1000);
  old.run('a2', USER_A, 'owner@example.test', 'sealed', Date.now() + 2000);
  old.run('b1', USER_B, 'other@example.test', 'sealed', Date.now() - 1000);
  old.run('gone', 'no-such-principal', 'nobody@example.test', 'sealed', Date.now() + 1000);
  store.db.exec("INSERT INTO oauth_flows VALUES ('flow','a1','sealed',0)");
  store.db.exec('PRAGMA user_version=36'); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual(next.db.prepare('SELECT address, principal_id FROM emails ORDER BY address').all().map(row => ({ ...row })),
    [{ address: 'other@example.test', principal_id: USER_B }, { address: 'owner@example.test', principal_id: USER_A }]);
  assert.equal(next.db.prepare('SELECT count(*) n FROM sessions').get().n, 0);
  assert.equal(next.db.prepare('SELECT count(*) n FROM oauth_flows').get().n, 0);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('37版のアドレスは、持ち主との結びつきだけを残して38版へ移る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-38-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  modules(store).principals.ensure(USER_A);
  store.db.exec(`DROP TABLE emails; CREATE TABLE emails (address TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, verified_at INTEGER NOT NULL);
    CREATE INDEX emails_principal ON emails(principal_id);`);
  store.db.prepare('INSERT INTO emails VALUES (?,?,?)').run('owner@example.test', USER_A, 1);
  store.db.exec('PRAGMA user_version=37'); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, 38);
  assert.deepEqual(next.db.prepare('SELECT * FROM emails').all().map(row => ({ ...row })), [{ address: 'owner@example.test', principal_id: USER_A }]);
});
