import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, stat, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';

const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', (part) => { out += part; }); child.stderr.on('data', (part) => { err += part; });
  child.once('error', reject); child.once('exit', (code) => resolve({ code, out, err }));
});

// The runtime is only what the agent cannot do for itself: make the key, and put what is kept into a command.
// Everything else it does over HTTP, with the key in that file.
const paths = account => [account.prefix + '/google-oauth-access-token', account.prefix + '/gmail-account-email'];

test('The runtime hands what is kept to the selected process only', async (t) => {
  const f = await fixture(t), account = await f.credential(), runtime = await f.agent();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-runtime-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal-readonly"||process.env.GMAIL_ACCOUNT_EMAIL!=="personal@example.test"||process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2);console.log("runtime-ready")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'runtime-ready');
  assert.doesNotMatch(run.out + run.err, /google-access|refresh_token|fdn_/);
  await f.request('/api/agents/' + runtime.id, { method: 'DELETE' });
  const revoked = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(revoked.code, 1);
  assert.doesNotMatch(revoked.out, /must-not-run/);
  await chmod(keyPath, 0o644);
  const unsafe = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(unsafe.code, 1);
  assert.match(unsafe.err, /private/);
});

test('connect makes the key as a private file, never printing it, and the same key is used from then on', async t => {
  const f = await fixture(t), account = await f.credential();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-pairing-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  await assert.rejects(stat(keyPath), { code: 'ENOENT' });
  const missing = await execute(['exec', ...paths(account), '--', process.execPath, '-e', '0'], env);
  assert.equal(missing.code, 1);
  assert.match(missing.err, /connect/);

  const connected = await execute(['connect', '--name', 'dev-us のAI'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out.slice(0, connected.out.indexOf('\n\nKey file'))).request, secret = (await readFile(keyPath, 'utf8')).trim();
  assert.equal(row.status, 'pending'); assert.equal(row.kind, 'approve');
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
  assert.ok(!connected.out.includes(secret), 'the key stays in the file');
  assert.match(connected.out, new RegExp(keyPath), 'and the agent is told where it is, for its own HTTP calls');

  const before = await execute(['exec', ...paths(account), '--', process.execPath, '-e', '0'], env);
  assert.equal(before.code, 1); assert.match(before.err, /not_approved/);
  const approval = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } });
  assert.equal(approval.status, 200, approval.text);
  const run = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'if(process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("connected")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'connected');
  assert.equal((await readFile(keyPath, 'utf8')).trim(), secret, 'connecting again never replaces a key that works');
  for (const result of [connected, before, run]) assert.doesNotMatch(result.out + result.err, /fdn_|google-access|refresh_token/);
});

test('CLI never overwrites or follows an existing insecure key file', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-keyfile-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const existing = join(dir, 'existing'), link = join(dir, 'link');
  await writeFile(existing, 'do-not-overwrite', { mode: 0o644 });
  let result = await execute(['connect'], { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: existing });
  assert.equal(result.code, 1);
  assert.match(result.err, /private/);
  assert.equal(await readFile(existing, 'utf8'), 'do-not-overwrite');
  await symlink(existing, link);
  result = await execute(['connect'], { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: link });
  assert.equal(result.code, 1);
  assert.match(result.err, /symbolic link/);
  assert.equal(await readFile(existing, 'utf8'), 'do-not-overwrite');
});

test('A denied request is indistinguishable from waiting, and asking again still works', async t => {
  const f = await fixture(t), account = await f.credential();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-denied-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const row = JSON.parse((await execute(['connect'], env)).out.split('\n\nKey file')[0]).request;
  await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} });
  const denied = await execute(['exec', ...paths(account), '--', process.execPath, '-e', '0'], env);
  assert.equal(denied.code, 1); assert.match(denied.err, /not_approved/, 'denial is indistinguishable from waiting');
  const again = JSON.parse((await execute(['connect'], env)).out.split('\n\nKey file')[0]).request;
  await f.request('/api/access-requests/' + again.id + '/approve', { method: 'POST', data: { confirmationCode: again.confirmation_code } });
  const after = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'console.log("ready")'], env);
  assert.equal(after.code, 0, after.err); assert.equal(after.out.trim(), 'ready');
});

test('--help describes the API, and when a server is reachable, what it can obtain itself', async t => {
  const f = await fixture(t);
  const offline = await execute(['--help'], { FOUNDATION_URL: '' });
  assert.equal(offline.code, 0, offline.err);
  assert.match(offline.out, /GET \/v1\/adapters lists what this server can obtain itself/);
  assert.match(offline.out, /Nothing here needs a shell/);
  assert.doesNotMatch(offline.out, /gmail/);
  const online = await execute(['--help'], { FOUNDATION_URL: f.base });
  assert.equal(online.code, 0, online.err);
  assert.match(online.out, /gmail.readonly  Gmail \/ メールの読み取り  keeps: GOOGLE_OAUTH_ACCESS_TOKEN/);
  assert.doesNotMatch(online.out, /expo\./, 'only what this server offers');
});

test('The server distributes its own CLI: install.sh bakes in the origin and the installed command runs against it', async t => {
  const f = await fixture(t);
  const script = await f.request('/cli/install.sh', { anonymous: true });
  assert.equal(script.status, 200);
  assert.match(script.text, new RegExp("ORIGIN='" + f.base + "'"));
  assert.match(script.text, /Node\.js 24/);
  assert.doesNotMatch(script.text, /__ORIGIN__|__FILES__/);
  const file = await f.request('/cli/runtime.mjs', { anonymous: true });
  assert.equal(file.status, 200);
  assert.equal(file.text, await readFile('src/runtime.mjs', 'utf8'));
  for (const bad of ['/cli/app.mjs', '/cli/../src/store.mjs', '/cli/store.mjs', '/cli/', '/cli/install.sh/']) assert.equal((await f.request(bad, { anonymous: true })).status, 404, bad);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-install-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'install.sh'), script.text);
  const run = (command, args, env) => new Promise((resolve) => {
    const child = spawn(command, args, { env: { ...process.env, ...env } });
    let out = '', err = ''; child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('exit', code => resolve({ code, out, err }));
  });
  const install = await run('sh', [join(dir, 'install.sh')], { FOUNDATION_CLI_DIR: join(dir, 'cli'), FOUNDATION_BIN_DIR: join(dir, 'bin') });
  assert.equal(install.code, 0, install.err);
  assert.match(install.out, /Installed/);
  const installed = await run(join(dir, 'bin', 'foundation'), ['--help'], { FOUNDATION_URL: f.base });
  assert.equal(installed.code, 0, installed.err);
  assert.match(installed.out, /gmail.readonly/);
});

test('FOUNDATION_AGENT gives each agent its own key file and default name', async t => {
  const f = await fixture(t), account = await f.credential();
  const home = await mkdtemp(join(tmpdir(), 'foundation-agent-home-')); t.after(() => rm(home, { recursive: true, force: true }));
  const base = { FOUNDATION_URL: f.base, HOME: home, FOUNDATION_RUNTIME_KEY_FILE: '' };
  const first = await execute(['connect'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(first.code, 0, first.err);
  const second = await execute(['connect'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(second.code, 0, second.err);
  const rows = [first, second].map(result => JSON.parse(result.out.split('\n\nKey file')[0]).request);
  assert.notEqual(rows[0].id, rows[1].id);
  assert.match(rows[0].requester_name, / の claude$/); assert.match(rows[1].requester_name, / の codex$/);
  const { readdir } = await import('node:fs/promises');
  const keys = (await readdir(join(home, '.local', 'state', 'foundation'))).sort();
  assert.equal(keys.length, 2); assert.ok(keys.some(name => name.endsWith('-claude.key')) && keys.some(name => name.endsWith('-codex.key')));
  const bad = await execute(['connect'], { ...base, FOUNDATION_AGENT: '../x' });
  assert.equal(bad.code, 1); assert.match(bad.err, /FOUNDATION_AGENT/);
  await f.request('/api/access-requests/' + rows[0].id + '/approve', { method: 'POST', data: { confirmationCode: rows[0].confirmation_code } });
  const approved = await execute(['exec', ...paths(account), '--', process.execPath, '-e', 'console.log("ready")'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(approved.code, 0, approved.err);
  const other = await execute(['exec', ...paths(account), '--', process.execPath, '-e', '0'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(other.code, 1); assert.match(other.err, /not_approved/, 'each key is approved on its own');
});
