import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Vault } from '../src/crypto.mjs';
import { KEY, USER_A } from './helpers.mjs';

// The schema a running Foundation is on today, fixed here so the step is tested against what it will meet.
const SCHEMA_26 = `
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
    kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect','app')), input TEXT NOT NULL,
    purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  CREATE TABLE holdings (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('grant','object','app')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
  CREATE UNIQUE INDEX holdings_object_name ON holdings(holder_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX holdings_app_name ON holdings(holder_id, name) WHERE kind='app';
  CREATE TABLE grants (
    holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')),
    connector TEXT, app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
  );
  CREATE INDEX grants_app ON grants(app_id) WHERE app_id IS NOT NULL;
  CREATE TABLE objects (holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  -- An OAuth app someone holds: which service it is for, its client ID, and its sealed secret (and eBay's RuName).
  CREATE TABLE apps (
    holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
    connector TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL, settings TEXT NOT NULL DEFAULT '{}'
  );
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = 26;
`;

test('26版のデータベースを、サービスとつなぎ方で持つ形へ移し、封を掛け直し、依頼と記録の言葉もそろえる', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path), vault = new Vault(KEY), stamp = '2026-09-01T00:00:00.000Z';
  db.exec(SCHEMA_26);
  db.prepare("INSERT INTO principals VALUES (?,?,?)").run(USER_A, 'owner', stamp);
  db.prepare("INSERT INTO principals VALUES ('agent','agent',?)").run(stamp);
  db.prepare("INSERT INTO credentials VALUES ('key-1','hash-1','agent','key',NULL,NULL,?,NULL)").run(stamp);
  const holding = db.prepare('INSERT INTO holdings VALUES (?,?,?,?,?,?)');
  const content = Buffer.from('secret-bytes');
  holding.run('secret-1', USER_A, 'grant', 'npm-token', stamp, stamp);
  db.prepare("INSERT INTO grants (holding_id,method,size,state) VALUES ('secret-1','given',?,?)").run(content.length, vault.sealBytes(content, 'grant:' + USER_A + ':secret-1'));
  const google = { private_state: { access_token: 'g' }, facts: { label: 'me@example.test' }, expires_at: null, requested_scopes: ['openid'] };
  holding.run('google-1', USER_A, 'grant', 'me@example.test', stamp, stamp);
  db.prepare("INSERT INTO grants VALUES ('google-1','authorized','google.oauth','foundation','me@example.test','usable',2,0,?)").run(vault.seal(google, 'grant:' + USER_A + ':google-1'));
  const aws = { private_state: { role_arn: 'arn' }, facts: { label: 'role' }, expires_at: null };
  holding.run('aws-1', USER_A, 'grant', 'role', stamp, stamp);
  db.prepare("INSERT INTO grants VALUES ('aws-1','delegated','aws.role',NULL,'aws:1:role','usable',1,0,?)").run(vault.seal(aws, 'grant:' + USER_A + ':aws-1'));
  holding.run('app-1', USER_A, 'app', 'Notes', stamp, stamp);
  db.prepare("INSERT INTO apps VALUES ('app-1','oauth2','notes-client',?,?)").run(vault.seal({ client_secret: 's' }, 'app:' + USER_A + ':app-1'),
    JSON.stringify({ service_name: 'Notes', authorize_url: 'https://notes.example/authorize', token_url: 'https://notes.example/token', userinfo_url: 'https://notes.example/me' }));
  const notes = { private_state: { access_token: 'n' }, facts: { label: 'n@example.test' }, expires_at: null };
  holding.run('notes-1', USER_A, 'grant', 'n@example.test', stamp, stamp);
  db.prepare("INSERT INTO grants VALUES ('notes-1','authorized','oauth2','app-1','user:n','usable',1,0,?)").run(vault.seal(notes, 'grant:' + USER_A + ':notes-1'));
  holding.run('object-1', USER_A, 'object', 'a.txt', stamp, stamp);
  db.prepare("INSERT INTO objects VALUES ('object-1',3,'text/plain')").run();
  db.prepare("INSERT INTO relations VALUES ('agent','viewer','holding','secret-1',NULL,NULL,?)").run(stamp);
  db.prepare("INSERT INTO records VALUES ('r1',?,?,'connection.created','grant','google-1',?)").run(stamp, USER_A, JSON.stringify({ connector: 'google.oauth' }));
  db.prepare("INSERT INTO records VALUES ('r2',?,'agent','delivery','principal',?,?)").run(stamp, USER_A, JSON.stringify({ names: ['npm-token'] }));
  db.prepare("INSERT INTO records VALUES ('r3',?,?,'credential.revoked','principal','agent',?)").run(stamp, USER_A, JSON.stringify({ credential: 'key-0' }));
  db.prepare("INSERT INTO requests (id,from_id,to_id,kind,input,purpose,steps,progress,result,status,created_at,expires_at) VALUES ('q1','agent',?,'connect',?,'p','[]',?,?,'done',0,?)")
    .run(USER_A, JSON.stringify({ connector: 'google.oauth', connection_id: 'google-1' }), JSON.stringify([{ event: 'connected', connector: 'google.oauth', at: 1 }]), JSON.stringify({ connection_id: 'google-1' }), Date.now() + 3_600_000);
  db.prepare("INSERT INTO sessions VALUES ('s',?,'me@example.test','x',?)").run(USER_A, Date.now() + 60_000);
  db.prepare("INSERT INTO oauth_flows VALUES ('flow','s',?,?)").run('x', Date.now() + 60_000);
  db.close();

  const store = new Store(path, KEY);
  t.after(() => store.close());
  const one = sql => store.db.prepare(sql).get(), all = sql => store.db.prepare(sql).all();
  assert.equal(one('PRAGMA user_version').user_version, 27);
  assert.deepEqual(all("SELECT id, kind FROM resources WHERE kind<>'service' ORDER BY id").map(row => [row.id, row.kind]),
    [['app-1', 'app'], ['aws-1', 'credential'], ['google-1', 'credential'], ['notes-1', 'credential'], ['object-1', 'object'], ['secret-1', 'credential']]);
  const credential = id => one("SELECT * FROM credentials WHERE resource_id='" + id + "'");
  assert.equal(credential('secret-1').service, null);
  assert.deepEqual(vault.openBytes(credential('secret-1').state, 'credential:' + USER_A + ':secret-1'), content);
  assert.deepEqual([credential('google-1').service, credential('google-1').auth_scheme, credential('google-1').app_id, credential('google-1').generation], ['google', 'oauth', 'foundation', 2]);
  assert.deepEqual(vault.open(credential('google-1').state, 'credential:' + USER_A + ':google-1'), google);
  assert.deepEqual([credential('aws-1').service, credential('aws-1').auth_scheme], ['aws', 'role']);
  // The generic app's service becomes a service its holder described, and the app and its credential point at it.
  const described = one("SELECT r.id, r.name, s.definition FROM resources r JOIN services s ON s.resource_id=r.id");
  assert.equal(described.name, 'Notes');
  assert.deepEqual(JSON.parse(described.definition).auth_schemes.oauth.identity, { url: 'https://notes.example/me' });
  assert.equal(one("SELECT service FROM apps WHERE resource_id='app-1'").service, described.id);
  assert.deepEqual([credential('notes-1').service, credential('notes-1').app_id], [described.id, 'app-1']);
  assert.equal(one("SELECT object_type FROM relations WHERE subject_id='agent'").object_type, 'resource');
  assert.equal(one("SELECT principal_id FROM access_keys WHERE id='key-1'").principal_id, 'agent');
  const entries = Object.fromEntries(all('SELECT * FROM audit_log').map(row => [row.id, { ...row, detail: JSON.parse(row.detail) }]));
  assert.deepEqual([entries.r1.action, entries.r1.object_type, entries.r1.detail], ['credential.created', 'credential', { service: 'google' }]);
  assert.equal(entries.r2.action, 'injection');
  assert.deepEqual([entries.r3.action, entries.r3.detail], ['key.revoked', { key: 'key-0' }]);
  const request = one("SELECT * FROM requests WHERE id='q1'");
  assert.deepEqual(JSON.parse(request.input), { service: 'google', credential_id: 'google-1', auth_scheme: 'oauth' });
  assert.deepEqual(JSON.parse(request.result), { credential_id: 'google-1' });
  assert.equal(JSON.parse(request.progress)[0].service, 'google');
  assert.equal(one('SELECT count(*) AS n FROM oauth_flows').n, 0);
  assert.equal(Object.values(one('PRAGMA integrity_check'))[0], 'ok');
  assert.deepEqual(all('PRAGMA foreign_key_check'), []);
});

test('もう誰も動かしていない形のデータベースは、移行せずに断る', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.sqlite'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE secrets (id TEXT); PRAGMA user_version = 25;');
  db.close();
  assert.throws(() => new Store(path, KEY), /not created by this version/);
});
