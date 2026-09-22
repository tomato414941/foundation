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
  const f = await fixture(t, { database }), account = await f.credential(), agent = await f.agent();
  const cookie = f.cookie();
  await f.start();
  const contents = await readFile(database);
  for (const value of ['google-access-personal', 'refresh-personal', 'supabase-access-owner', 'supabase-refresh-owner', agent.token, cookie.slice(12)]) assert.ok(!contents.includes(Buffer.from(value)), value);
  const second = new Store(database, KEY); t.after(() => second.close());
  assert.equal(second.secret(second.credential(USER_A, account.id)).refresh_token, 'refresh-personal-readonly');
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

test('A new database is created in the current shape; a database of any other shape is refused and left unchanged', async (t) => {
  const dir = await directory(t), path = join(dir, 'state.sqlite');
  const created = new Store(path, KEY);
  const id = created.register(USER_A, { adapter: 'gmail.readonly', service: 'Gmail', subject: 'kept@example.test', name: 'kept', purpose: '' }, { refresh_token: 'keep-private' });
  const agent = created.addAgent(USER_A, 'runtime');
  created.recordIssuance(agent, null);
  created.close();
  const reopened = new Store(path, KEY); t.after(() => reopened.close());
  assert.equal(reopened.secret(reopened.credential(USER_A, id)).refresh_token, 'keep-private');
  assert.equal(reopened.agents(USER_A)[0].issued_nonexpiring, 1);
  for (const shape of ['CREATE TABLE accounts(id TEXT); INSERT INTO accounts VALUES (\'existing\');', 'CREATE TABLE accounts(id TEXT); PRAGMA user_version=6;', 'PRAGMA user_version=2;']) {
    const other = join(dir, 'other-' + Math.random().toString(36).slice(2) + '.sqlite'), db = new DatabaseSync(other);
    db.exec(shape); db.close();
    assert.throws(() => new Store(other, KEY), /not created by this version/, shape);
    const after = new DatabaseSync(other);
    assert.equal(after.prepare('PRAGMA user_version').get().user_version, /user_version=(\d)/.exec(shape)?.[1] * 1 || 0);
    after.close();
  }
});
