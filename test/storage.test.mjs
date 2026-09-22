import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, readdir, unlink } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration } from '../src/config.mjs';
import { Store } from '../src/store.mjs';
import { Vault } from '../src/crypto.mjs';
import { fixture, KEY, USER_A } from './helpers.mjs';

async function directory(t) { const path = await mkdtemp(join(tmpdir(), 'foundation-auth-test-')); t.after(() => rm(path, { recursive: true, force: true })); return path; }

test('Gmail and Supabase secrets are encrypted; keys and cookies never persist in plaintext', async (t) => {
  const dir = await directory(t), database = join(dir, 'state.sqlite');
  const f = await fixture(t, { database }), account = await f.account(), agent = await f.agent();
  const cookie = f.cookie();
  await f.start();
  const contents = await readFile(database);
  for (const value of ['google-access-personal', 'refresh-personal', 'supabase-access-owner', 'supabase-refresh-owner', agent.token, cookie.slice(12)]) assert.ok(!contents.includes(Buffer.from(value)), value);
  const second = new Store(database, KEY); t.after(() => second.close());
  assert.equal(second.secrets(second.account(USER_A, account.id)).refresh_token, 'refresh-personal-readonly');
  assert.ok(second.session(cookie.slice(12)));
  assert.equal(second.authenticate(agent.token).owner_id, USER_A);
  const tables = second.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((item) => item.name);
  assert.ok(!tables.some((name) => /mail|message|log|body/.test(name)));
  assert.equal((await stat(database)).mode & 0o777, 0o600);
});

test('Authenticated encryption binds ciphertext to its account and owner', () => {
  const vault = new Vault(KEY), data = vault.seal({ refresh_token: 'secret' }, 'account:A');
  assert.deepEqual(vault.open(data, 'account:A'), { refresh_token: 'secret' });
  assert.throws(() => vault.open(data, 'account:B'));
  assert.throws(() => new Vault(Buffer.alloc(32, 8)).open(data, 'account:A'));
});

test('Configuration creates private encryption key, never an owner login key; losing key fails closed', async (t) => {
  const dir = await directory(t), env = { FOUNDATION_DATA_DIR: dir };
  const first = configuration(env), second = configuration(env);
  assert.equal(first.supabase.emailEnabled, false);
  assert.equal(configuration({ ...env, FOUNDATION_EMAIL_LOGIN_ENABLED: 'true' }).supabase.emailEnabled, true);
  assert.deepEqual(first.encryptionKey, second.encryptionKey);
  assert.equal((await stat(join(dir, 'encryption-key'))).mode & 0o777, 0o600);
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
  assert.ok(!(await readdir(dir)).includes('owner-key'));
  const db = new Store(first.database, first.encryptionKey); db.close();
  assert.throws(() => new Store(first.database, KEY));
  await unlink(join(dir, 'encryption-key'));
  assert.throws(() => configuration(env), /original encryption key/);
});

test('Old data cannot be reassigned to the first Supabase login; empty legacy schema upgrades', async (t) => {
  const dir = await directory(t), path = join(dir, 'legacy.sqlite');
  let db = new DatabaseSync(path);
  db.exec('CREATE TABLE accounts(id TEXT); CREATE TABLE agents(id TEXT); CREATE TABLE grants(id TEXT); INSERT INTO accounts VALUES (\'existing\'); PRAGMA user_version=1;'); db.close();
  assert.throws(() => new Store(path, KEY), /explicit owner migration/);
  db = new DatabaseSync(path);
  assert.equal(db.prepare('SELECT count(*) n FROM accounts').get().n, 1);
  db.exec('DELETE FROM accounts'); db.close();
  const upgraded = new Store(path, KEY);
  assert.equal(upgraded.db.prepare('PRAGMA user_version').get().user_version, 6); upgraded.close();
});

test('Version 2 upgrade preserves encrypted connections and runtime keys', async t => {
  const dir = await directory(t), path = join(dir, 'upgrade.sqlite');
  const first = new Store(path, KEY);
  const id = first.connect(USER_A, { email: 'upgrade@example.test', name: 'existing', purpose: '', scopes: ['readonly'] }, { refresh_token: 'keep-private' });
  const agent = first.addAgent(USER_A, 'existing-runtime');
  first.db.exec('DROP TABLE access_requests; PRAGMA user_version=2;');
  first.close();
  const upgraded = new Store(path, KEY); t.after(() => upgraded.close());
  assert.equal(upgraded.db.prepare('PRAGMA user_version').get().user_version, 6);
  assert.equal(upgraded.secrets(upgraded.account(USER_A, id)).refresh_token, 'keep-private');
  assert.equal(upgraded.authenticate(agent.token).id, agent.id);
  assert.equal(upgraded.agents(USER_A)[0].name, 'existing-runtime');
  assert.equal(upgraded.db.prepare('SELECT count(*) n FROM access_requests').get().n, 0);
});

test('Version 3 adds nonexpiring-key audit without changing credentials', async t => {
  const dir = await directory(t), path = join(dir, 'v3.sqlite');
  const first = new Store(path, KEY);
  const id = first.connect(USER_A, { email: 'v3@example.test', name: 'existing', purpose: '', scopes: ['readonly'] }, { access_token: 'keep-encrypted', expires_at: Date.now() + 3600_000 });
  const agent = first.addAgent(USER_A, 'existing');
  first.recordIssuance(agent, 1000);
  first.db.exec('ALTER TABLE agents DROP COLUMN issued_nonexpiring; PRAGMA user_version=3;');
  first.close();
  const upgraded = new Store(path, KEY); t.after(() => upgraded.close());
  assert.equal(upgraded.db.prepare('PRAGMA user_version').get().user_version, 6);
  assert.equal(upgraded.secrets(upgraded.account(USER_A, id)).access_token, 'keep-encrypted');
  assert.equal(upgraded.agents(USER_A)[0].issued_nonexpiring, 0);
  upgraded.recordIssuance(agent, null); upgraded.recordIssuance(agent, 2000);
  assert.equal(upgraded.agents(USER_A)[0].issued_nonexpiring, 1);
  assert.equal(upgraded.agents(USER_A)[0].issued_until, 2000);
});
