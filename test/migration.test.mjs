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
import { Environments } from '../src/environments.mjs';
import { Payments, Stripe } from '../src/payments.mjs';
import { KEY, USER_A, USER_B, modules } from './helpers.mjs';

const STORED_SERVICE = { version: 1, name: 'Stored service', auth_schemes: { oauth: {
  authorize: 'https://service.example/authorize', token: 'https://service.example/token', keep: ['id'], ok_field: 'ok',
  identity: { url: '{id}', id: ['data.viewer.id', 'organization_id'], label: ['data.viewer.email'] },
  injection: { ACCESS_TOKEN: '{access_token}', ACCOUNT: '{account}', EXPIRES_AT: '{expires_at}' },
} } };

// A connection's state is sealed under its name, so it is compared by what it opens to instead.
// A secret's bytes are sealed anew by 43, so they are compared by what they open to instead.
const m2 = store => modules(store);
const SNAPSHOT_COLUMNS = { credentials: 'resource_id,service,auth_scheme,app_id,subject,status,generation', secrets: 'resource_id,generation' };

async function storedDefinitions(t, definitions) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-reference-migration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), m = modules(store);
  const secret = m.secrets.putAs(USER_A, { name: 'token#work', content: Buffer.from([0, 255, 10, 42]) });
  // Back to how a secret was kept before 43: sealed by the server under its name.
  store.db.prepare('UPDATE secrets SET content=? WHERE resource_id=?').run(new Vault(KEY).sealBytes(Buffer.from([0, 255, 10, 42]), `secret:${USER_A}:${secret.id}`), secret.id);
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
  for (const row of store.db.prepare('SELECT c.resource_id, c.state, r.owner_id FROM connections c JOIN resources r ON r.id=c.resource_id').all()) {
    store.db.prepare('UPDATE connections SET state=? WHERE resource_id=?').run(vault.seal(JSON.parse(m.keys.openFor(row.resource_id, Buffer.from(row.state)).toString()), `credential:${row.owner_id}:${row.resource_id}`), row.resource_id);
  }
  store.db.exec('DROP INDEX connections_app; ALTER TABLE connections RENAME TO credentials; CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;');
  store.db.exec(`ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP TABLE meter_events; DROP TABLE payment_accounts; DROP TABLE webauthn_credentials; DROP TABLE emails; DROP TABLE challenges; DROP TABLE oauth_flows; DROP TABLE sessions;
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
    // 43 adds one line: Foundation's principal as agent of each holder whose secrets it had been opening.
    // 45 renames the column that says whose a resource is.
    const renamed = expected.map(row => Object.hasOwn(row, 'holder_id') ? { ...Object.fromEntries(Object.entries(row).filter(([key]) => key !== 'holder_id')), owner_id: row.holder_id } : { ...row });
    assert.deepEqual(store.db.prepare(`SELECT ${SNAPSHOT_COLUMNS[table] ?? '*'} FROM ${now}`).all().filter(row => !(table === 'relations' && row.relation === 'agent' && row.subject_id === m2(store).keys.agentId)).map(row => ({ ...row })), renamed, table);
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
  assert.deepEqual(m.secrets.open(m.secrets.get(old.secret.id)), Buffer.from([0, 255, 10, 42]));
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
  // One action drawn onto a thing is that action's own relation; one drawn onto a principal, reaching all it holds, has no place and is dropped (42).
  assert.deepEqual(lines.map(row => row.relation), ['agent', 'owner', 'remove_grant', 'viewer'], 'what was done to a principal as a whole is its own action');
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
  assert.deepEqual(secrets.open(secrets.get('plain')), bytes);
  assert.equal(secrets.get('plain').name, 'same name');
  assert.equal(secrets.get('plain').generation, 7);
  assert.equal(secrets.get('single').name, 'same name (single)');
  assert.equal(secrets.open(secrets.get('single')).toString(), 'single-token');
  assert.deepEqual(JSON.parse(secrets.open(secrets.get('multi')).toString()), fields);
  assert.deepEqual(connections.state(connections.get('oauth')), managed);
  assert.equal(connections.get('oauth').generation, 7);
  assert.equal(connections.state(connections.get('role')).private_state.role_arn, 'arn:aws:iam::123456789012:role/fixture');
  assert.equal(services.get('12345678-1234-4234-8234-123456789012').definition.name, 'Notes');
  const allowed = (action, id, type = 'secret') => authorization.can(old.reader, action, type, { owner: USER_A, id });
  assert.equal(allowed('content', 'plain'), true);
  assert.equal(allowed('write', 'plain'), true);
  assert.equal(allowed('read', 'single'), true);
  assert.equal(allowed('content', 'single'), false, 'a former metadata viewer still cannot read the private value');
  assert.equal(allowed('write', 'single'), false);
  assert.equal(allowed('remove', 'single'), true);
  assert.equal(allowed('rename', 'oauth', 'connection'), true);
  // An action that was drawn onto the holder, reaching all they hold, has no place in the schema and is gone (42).
  assert.equal(authorization.can(old.reader, 'list', 'secret', { owner: USER_A }), false);
  assert.equal(authorization.can(old.reader, 'list', 'connection', { owner: USER_A }), false);
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
  store.db.exec(`ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP TABLE meter_events; DROP TABLE payment_accounts; DROP TABLE webauthn_credentials; DROP TABLE emails; DROP TABLE challenges; DROP TABLE oauth_flows; DROP TABLE sessions;
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

test('37版のアドレスは、持ち主との結びつきだけを残して移る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-38-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  modules(store).principals.ensure(USER_A);
  store.db.exec(`ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP TABLE meter_events; DROP TABLE payment_accounts; DROP TABLE webauthn_credentials; DROP TABLE emails; CREATE TABLE emails (address TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, verified_at INTEGER NOT NULL);
    CREATE INDEX emails_principal ON emails(principal_id);`);
  store.db.prepare('INSERT INTO emails VALUES (?,?,?)').run('owner@example.test', USER_A, 1);
  store.db.exec('PRAGMA user_version=37'); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual(next.db.prepare('SELECT address, principal_id FROM emails').all().map(row => ({ ...row })), [{ address: 'owner@example.test', principal_id: USER_A }]);
});

test('39版のパスキーの表はWebAuthnの資格情報の表になり、それで証明したセッションは続く', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-40-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  modules(store).principals.ensure(USER_A);
  store.db.exec(`ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP TABLE meter_events; DROP TABLE payment_accounts; DROP TABLE webauthn_credentials; DROP TABLE challenges; DROP TABLE oauth_flows; DROP TABLE sessions;
    CREATE TABLE passkeys (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL,
      sign_count INTEGER NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER);
    CREATE INDEX passkeys_principal ON passkeys(principal_id);
    CREATE TABLE sessions (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
      proof TEXT NOT NULL CHECK(proof IN ('email','key','passkey')), proof_ref TEXT NOT NULL, proved_at INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','passkey')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);`);
  store.db.prepare('INSERT INTO passkeys VALUES (?,?,?,?,?,?,?)').run('credential-1', USER_A, Buffer.from([1, 2, 3]), 4, 'この端末', 1, 2);
  store.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?,?,?)').run('by-passkey', USER_A, 'passkey', 'credential-1', 1, 1, Date.now() + 3600_000);
  store.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?,?,?)').run('by-email', USER_A, 'email', 'owner@example.test', 1, 1, Date.now() + 3600_000);
  store.db.exec("INSERT INTO challenges VALUES ('waiting','passkey','signin',NULL,'{}',1,9999999999999); DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=39"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual({ ...next.db.prepare('SELECT id, principal_id, sign_count, name FROM webauthn_credentials').get() }, { id: 'credential-1', principal_id: USER_A, sign_count: 4, name: 'この端末' });
  assert.deepEqual(next.db.prepare('SELECT id, proof, proof_ref FROM sessions ORDER BY id').all().map(row => ({ ...row })),
    [{ id: 'by-email', proof: 'email', proof_ref: 'owner@example.test' }, { id: 'by-passkey', proof: 'webauthn', proof_ref: 'credential-1' }]);
  assert.equal(next.db.prepare('SELECT count(*) n FROM challenges').get().n, 0);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('41版の代わりに動く線は agent に、一つの操作の線はその操作の関係になり、持ち主へ引いた操作の線は消える', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-42-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  const { principals } = modules(store);
  principals.ensure(USER_A); principals.ensure(USER_B);
  const line = store.db.prepare('INSERT INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,?,?,?,?)');
  line.run(USER_B, 'actor', 'principal', USER_A, '2026-01-01'); line.run(USER_A, 'owner', 'principal', USER_B, '2026-01-01');
  line.run(USER_B, 'connection.disconnect', 'resource', 'c1', '2026-01-01'); line.run(USER_B, 'connection.disconnect', 'principal', USER_A, '2026-01-01');
  line.run(USER_B, 'viewer', 'resource', 's1', '2026-01-01');
  store.db.prepare("INSERT INTO requests (id,from_id,to_id,type,detail,binding_message,steps,status,result,created_at,expires_at) VALUES ('r1',?,?,'relation',?,'','[]','granted',?,0,9999999999999)")
    .run(USER_B, USER_A, JSON.stringify({ relation: 'actor' }), JSON.stringify({ relation: 'actor', object_type: 'principal', object_id: USER_A }));
  store.db.exec("ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=41"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual(next.db.prepare('SELECT relation, object_type, object_id FROM relations ORDER BY relation, object_id').all().map(row => ({ ...row })),
    [{ relation: 'agent', object_type: 'principal', object_id: USER_A }, { relation: 'disconnect_grant', object_type: 'resource', object_id: 'c1' },
      { relation: 'owner', object_type: 'principal', object_id: USER_B }, { relation: 'viewer', object_type: 'resource', object_id: 's1' }]);
  const request = next.db.prepare("SELECT detail, result FROM requests WHERE id='r1'").get();
  assert.equal(JSON.parse(request.detail).relation, 'agent'); assert.equal(JSON.parse(request.result).relation, 'agent');
});

test('40版の環境は ID・コマンド・鍵・使用量を保って停止再試行可能な43版へ移る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-43-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), m = modules(store);
  m.principals.ensure(USER_A);
  store.db.exec(`DROP TABLE environments;
    CREATE TABLE environments (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
      identity TEXT, runner TEXT NOT NULL, machine TEXT,
      status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopped')),
      started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );`);
  const expires = Date.now() + 3600_000;
  for (const status of ['starting', 'ready', 'busy', 'stopped']) {
    m.resources.insert(status, USER_A, 'environment', status);
    store.db.prepare('INSERT INTO environments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(status, 'small', 'idle', 30, 3600, USER_A, 'fly', status === 'starting' ? null : 'machine-' + status, status, 10, 20, expires);
  }
  m.principals.issueKey(USER_A, { environmentId: 'busy', expiresAt: expires });
  store.db.prepare("INSERT INTO environment_commands VALUES ('command','busy',?,'[\"true\"]','running',NULL,NULL,NULL,10,NULL)").run(USER_A);
  store.db.prepare("INSERT INTO compute_usage VALUES (?,'2026-10',23)").run(USER_A);
  const tables = ['resources', 'environment_commands', 'access_keys', 'compute_usage'];
  const before = Object.fromEntries(tables.map(table => [table, store.db.prepare('SELECT * FROM ' + table).all()]));
  const rows = store.db.prepare('SELECT * FROM environments ORDER BY resource_id').all();
  store.db.exec("ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP TABLE meter_events; DROP TABLE payment_accounts; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=40"); store.close();
  let next = new Store(path, KEY);
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  for (const table of tables) assert.deepEqual(next.db.prepare('SELECT * FROM ' + table).all(), before[table], table);
  assert.deepEqual(next.db.prepare('SELECT * FROM environments ORDER BY resource_id').all().map(row => ({ ...row })),
    rows.map(row => ({ ...row, stop_attempts: 0, stop_retry_at: null, remove_requested: 0 })));
  next.db.prepare("UPDATE environments SET status='stopping',stop_attempts=1,stop_retry_at=?,remove_requested=1 WHERE resource_id='busy'").run(expires);
  assert.equal(next.db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
  next.close(); next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare("SELECT status FROM environments WHERE resource_id='busy'").get().status, 'stopping');
  assert.equal(next.db.prepare("SELECT stop_attempts FROM environments WHERE resource_id='busy'").get().stop_attempts, 1);
});

test('本番41版の支払い登録と送信済み・未送信イベントは、43版の停止移行で変わらない', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-payment-stop-migration-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), m = modules(store);
  m.principals.ensure(USER_A);
  store.db.exec(`DROP TABLE environments;
    CREATE TABLE environments (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
      identity TEXT, runner TEXT NOT NULL, machine TEXT,
      status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopped')),
      started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );`);
  for (const status of ['ready', 'stopped']) {
    m.resources.insert(status, USER_A, 'environment', status);
    store.db.prepare('INSERT INTO environments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(status, 'small', 'idle', 30, 3600, null, 'fly', 'machine-' + status, status, 10, 20, Date.now() + 3600_000);
  }
  store.db.prepare("INSERT INTO payment_accounts VALUES (?,'cus_1','sub_1','active',1)").run(USER_A);
  store.db.prepare("INSERT INTO meter_events VALUES ('sent',?,'compute',23,100,200)").run(USER_A);
  store.db.prepare("INSERT INTO meter_events VALUES ('pending',?,'compute',7,300,NULL)").run(USER_A);
  store.db.prepare("INSERT INTO compute_usage VALUES (?,'2026-10',30)").run(USER_A);
  const tables = ['payment_accounts', 'meter_events', 'compute_usage'];
  const before = Object.fromEntries(tables.map(table => [table, store.db.prepare('SELECT * FROM ' + table).all()]));
  store.db.exec("ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=41"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  for (const table of tables) assert.deepEqual(next.db.prepare('SELECT * FROM ' + table).all(), before[table], table);
  assert.equal(next.db.prepare("SELECT status FROM environments WHERE resource_id='stopped'").get().status, 'stopped');
  assert.equal(next.db.prepare("SELECT stop_attempts FROM environments WHERE resource_id='ready'").get().stop_attempts, 0);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('mainの42版DBは認可と課金を保って43版へ移り、停止の読み取りと再試行が動く', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-main42-stop-migration-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), m = modules(store), now = Date.now();
  m.principals.ensure(USER_A); m.principals.ensure(USER_B);
  // All other tables have main's v42 shape. Only environments gained columns/a status in v43.
  store.db.exec(`DROP TABLE environments;
    CREATE TABLE environments (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
      identity TEXT, runner TEXT NOT NULL, machine TEXT,
      status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopped')),
      started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );`);
  m.resources.insert('environment-42', USER_A, 'environment', 'kept environment');
  store.db.prepare('INSERT INTO environments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
    .run('environment-42', 'medium', 'idle', 30, 3600, USER_A, 'fake', 'machine-42', 'ready', now - 10_000, now, now + 3600_000);
  m.principals.issueKey(USER_A, { environmentId: 'environment-42', expiresAt: now + 3600_000 });
  const line = store.db.prepare('INSERT INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,?,?,?,?)');
  line.run(USER_B, 'agent', 'principal', USER_A, '2026-01-01');
  line.run(USER_B, 'exec_grant', 'resource', 'environment-42', '2026-01-01');
  line.run(USER_A, 'owner', 'principal', USER_B, '2026-01-01');
  store.db.prepare("INSERT INTO requests (id,from_id,to_id,type,detail,binding_message,steps,status,result,created_at,expires_at) VALUES ('r42',?,?,'relation',?,'','[]','granted',?,0,9999999999999)")
    .run(USER_B, USER_A, JSON.stringify({ relation: 'agent' }), JSON.stringify({ relation: 'agent', object_type: 'principal', object_id: USER_A }));
  store.db.prepare("INSERT INTO environment_commands VALUES ('command-42','environment-42',?,'[\"true\"]','done',0,'kept','',?,?)").run(USER_A, now - 1000, now);
  store.db.prepare("INSERT INTO payment_accounts VALUES (?,'cus_42','sub_42','active',1)").run(USER_A);
  store.db.prepare("INSERT INTO meter_events VALUES ('sent-42',?,'compute',23,100,200)").run(USER_A);
  store.db.prepare("INSERT INTO meter_events VALUES ('pending-42',?,'compute',7,300,NULL)").run(USER_A);
  store.db.prepare('INSERT INTO compute_usage VALUES (?,?,30)').run(USER_A, new Date(now).toISOString().slice(0, 7));
  const tables = ['resources', 'relations', 'requests', 'environment_commands', 'access_keys', 'payment_accounts', 'meter_events', 'compute_usage'];
  const before = Object.fromEntries(tables.map(table => [table, store.db.prepare('SELECT * FROM ' + table).all()]));
  store.db.exec("ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=42"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  for (const table of tables) assert.deepEqual(next.db.prepare('SELECT * FROM ' + table).all(), before[table], table);
  const modules43 = modules(next), payments = new Payments(next, new Stripe());
  assert.equal(modules43.authorization.can(USER_B, 'exec', 'environment', { id: 'environment-42', owner: USER_A }), true);
  let calls = 0;
  const runner = { name: 'fake', async stop(machine) { assert.equal(machine, 'machine-42'); if (++calls === 1) throw new Error('retry'); } };
  const environments = new Environments({ store: next, ...modules43, payments, runner });
  const row = environments.get('environment-42');
  assert.equal(row.stop_attempts, 0); assert.equal(row.stop_retry_at, null); assert.equal(row.remove_requested, 0);
  await environments.stop(row);
  assert.equal(environments.get(row.id).status, 'stopping');
  assert.equal(modules43.principals.keys(USER_A).filter(key => key.environment_id === row.id).length, 0);
  assert.deepEqual(next.db.prepare('SELECT * FROM meter_events').all(), before.meter_events);
  await environments.sweep(environments.get(row.id).stop_retry_at);
  assert.equal(environments.get(row.id).status, 'stopped'); assert.equal(calls, 2);
  const settled = next.db.prepare('SELECT * FROM meter_events').all(); assert.equal(settled.length, 3);
  await environments.stop(row); assert.deepEqual(next.db.prepare('SELECT * FROM meter_events').all(), settled);
  assert.equal(next.db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('43版のシークレットはそれぞれの鍵で封じ直され、開いていたFoundationの封筒だけが残り、Foundationは持ち主の代わりに動く線を得る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-43-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), vault = new Vault(KEY);
  const { principals, resources } = modules(store);
  principals.ensure(USER_A); principals.ensure(USER_B);
  // Two secrets of the owner's and one of another's, sealed as the server did before 44; the other keeps none.
  const kept = [['s1', USER_A, 'one'], ['s2', USER_A, 'two'], ['s3', USER_B, 'three']];
  for (const [id, holder, value] of kept) {
    resources.insert(id, holder, 'secret', id);
    store.db.prepare('INSERT INTO secrets (resource_id,size,content) VALUES (?,?,?)').run(id, value.length, vault.sealBytes(Buffer.from(value), `secret:${holder}:${id}`));
  }
  store.db.exec("ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP TABLE connection_references; DROP TABLE envelopes; DROP TABLE key_wraps; DROP TABLE principal_keys; DELETE FROM principals WHERE name='Foundation'; DELETE FROM metadata WHERE name LIKE 'agent_%'; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=43");
  store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  const m = modules(next);
  for (const [id, , value] of kept) {
    assert.equal(m.secrets.open(m.secrets.get(id)).toString(), value);
    assert.deepEqual(m.keys.recipientsOf(id), [m.keys.agentId], 'sealed for Foundation alone until the holder seals it for a key of their own');
    assert.equal(m.secrets.get(id).size, value.length + 28);
  }
  assert.deepEqual(next.db.prepare("SELECT subject_id, object_id FROM relations WHERE relation='agent' ORDER BY object_id").all().map(row => ({ ...row })),
    [{ subject_id: m.keys.agentId, object_id: USER_A }, { subject_id: m.keys.agentId, object_id: USER_B }]);
  assert.equal(next.db.prepare("SELECT name FROM principals WHERE id=?").get(m.keys.agentId).name, 'Foundation');
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('44版の持ち物の列は owner_id になり、持ち物も線も封筒もそのまま残る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-45-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  const { principals, resources, secrets } = modules(store);
  principals.ensure(USER_A); principals.ensure(USER_B);
  const kept = secrets.putAs(USER_A, { name: 'mine', content: Buffer.from('v') });
  resources.insert('o1', USER_B, 'object', 'theirs');
  principals.relate(USER_B, 'viewer', 'resource', kept.id);
  const before = store.db.prepare('SELECT id, owner_id, kind, name FROM resources ORDER BY id').all().map(row => ({ ...row }));
  store.db.exec("DROP TABLE connection_references; ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at); DROP INDEX resources_owner; ALTER TABLE resources RENAME COLUMN owner_id TO holder_id; CREATE INDEX resources_holder ON resources(holder_id, kind, name); DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=44"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual(next.db.prepare('SELECT id, owner_id, kind, name FROM resources ORDER BY id').all().map(row => ({ ...row })), before);
  assert.ok(next.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='index' AND name='resources_owner'").get());
  const m = modules(next);
  assert.equal(m.secrets.open(m.secrets.get(kept.id)).toString(), 'v');
  assert.equal(m.authorization.can(USER_B, 'read', 'secret', { id: kept.id, owner: USER_A }), true, 'the line onto it holds');
  assert.equal(m.authorization.can(USER_A, 'content', 'secret', { id: kept.id }), true, 'the owner, read from the column');
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('45版の確認値の表は、まとめる手続きの券も入る形になり、待っている確認値は残る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-46-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  store.db.exec("DROP TABLE connection_references; ALTER TABLE webauthn_credentials DROP COLUMN user_handle; DROP TABLE challenges; CREATE TABLE challenges (id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at);");
  store.db.prepare('INSERT INTO challenges VALUES (?,?,?,?,?,?,?)').run('c1', 'email', 'owner@example.test', null, '{}', 1, 9999999999999);
  modules(store).principals.ensure(USER_A);
  store.db.prepare('INSERT INTO webauthn_credentials (id,principal_id,public_key,sign_count,name,created_at) VALUES (?,?,?,?,?,?)').run('credential-0000000046', USER_A, Buffer.alloc(8), 0, 'phone', 1);
  store.db.exec('DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=45'); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.deepEqual({ ...next.db.prepare('SELECT id, purpose, subject FROM challenges').get() }, { id: 'c1', purpose: 'email', subject: 'owner@example.test' });
  next.db.prepare('INSERT INTO challenges VALUES (?,?,?,?,?,?,?)').run('c2', 'merge', 'a:b', null, '{}', 1, 9999999999999);
  assert.equal(next.db.prepare('SELECT user_handle FROM webauthn_credentials WHERE id=?').get('credential-0000000046').user_handle, USER_A, 'a credential keeps the handle it was made with: its principal then');
  assert.ok(next.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='index' AND name='challenges_subject'").get());
});

test('46版の接続の状態は、接続ごとの鍵で封じ直され、Foundation宛の封筒を持ち、開いて同じ中身になる', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-47-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY), vault = new Vault(KEY);
  const { principals, resources } = modules(store);
  principals.ensure(USER_A);
  resources.insert('c1', USER_A, 'connection', 'GitHub');
  const state = { private_state: { fields: { token: 'ghp_x' } }, facts: {}, expires_at: null };
  store.db.prepare("INSERT INTO connections (resource_id,service,auth_scheme,subject,status,generation,state) VALUES ('c1','github','token',NULL,'usable',3,?)").run(vault.seal(state, `connection:${USER_A}:c1`));
  store.db.exec("DROP TABLE connection_references; DELETE FROM envelopes; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=46"); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  const m = modules(next);
  assert.deepEqual(m.connections.state(m.connections.get('c1')), state);
  assert.deepEqual(m.keys.recipientsOf('c1'), [m.keys.agentId]);
  assert.equal(m.connections.get('c1').generation, 3);
  assert.deepEqual(next.db.prepare('PRAGMA foreign_key_check').all(), []);
});

test('47版に、接続が参照するシークレットの記録の表が加わる', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-migration-48-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), store = new Store(path, KEY);
  store.db.exec('DROP TABLE connection_references; DROP INDEX emails_id; ALTER TABLE emails DROP COLUMN id; ALTER TABLE emails DROP COLUMN created_at; PRAGMA user_version=47'); store.close();
  const next = new Store(path, KEY); t.after(() => next.close());
  assert.equal(next.db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  assert.ok(next.db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='connection_references'").get());
});
