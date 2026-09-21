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

test('Runtime discovers native Gmail and injects credentials only into selected process', async (t) => {
  const f = await fixture(t), account = await f.account(), runtime = await f.agent([account.id]);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-runtime-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const listed = await execute(['accounts'], env);
  assert.equal(listed.code, 0, listed.err);
  assert.equal(JSON.parse(listed.out).accounts[0].id, account.id);
  assert.doesNotMatch(listed.out, /google-access|refresh_token/);
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal-readonly"||process.env.GMAIL_ACCOUNT_EMAIL!=="personal@example.test"||process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2);console.log("runtime-ready")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'runtime-ready');
  assert.doesNotMatch(run.err, /google-access|refresh_token/);
  await f.request('/api/agents/' + runtime.id, { method: 'DELETE' });
  const revoked = await execute(['exec', account.id, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(revoked.code, 1);
  assert.doesNotMatch(revoked.out, /must-not-run/);
  await chmod(keyPath, 0o644);
  const unsafe = await execute(['accounts'], env);
  assert.equal(unsafe.code, 1);
  assert.match(unsafe.err, /private/);
});

test('CLI bootstraps and resumes approval without printing or manually copying a runtime key', async t => {
  const f = await fixture(t), account = await f.account();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-pairing-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const providers = await execute(['providers'], env);
  assert.equal(providers.code, 0, providers.err);
  assert.equal(JSON.parse(providers.out).providers[0].id, 'gmail');
  await assert.rejects(stat(keyPath), { code: 'ENOENT' });
  const missing = await execute(['accounts'], env);
  assert.equal(missing.code, 1);
  assert.match(missing.err, /connect/);
  const connected = await execute(['connect', '--name', 'dev-us のAI', '--purpose', 'メールの確認'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out).request, secret = (await readFile(keyPath, 'utf8')).trim();
  assert.equal(row.status, 'pending');
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
  assert.ok(!connected.out.includes(secret));
  const pending = await execute(['accounts'], env);
  assert.equal(pending.code, 1); assert.match(pending.err, /not_approved/);
  const approval = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  assert.equal(approval.status, 200, approval.text);
  assert.equal((await execute(['accounts'], env)).code, 0);
  assert.equal(JSON.parse((await execute(['accounts'], env)).out).accounts[0].id, account.id);
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', 'if(process.env.FOUNDATION_ACCESS_TOKEN!==process.env.GOOGLE_OAUTH_ACCESS_TOKEN || process.env.FOUNDATION_PROVIDER!=="gmail" || process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("connected")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'connected');
  assert.equal((await readFile(keyPath, 'utf8')).trim(), secret);
  for (const result of [connected, pending, run]) assert.doesNotMatch(result.out + result.err, /fdn_|google-access|refresh_token/);
  const next = await execute(['connect'], env);
  assert.equal(next.code, 0, next.err);
  const cancelled = await execute(['cancel'], env);
  assert.equal(JSON.parse(cancelled.out).request.status, 'cancelled');
  assert.equal((await execute(['accounts'], env)).code, 0, 'cancelling a new request does not revoke an earlier grant');
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

test('accounts answers 401 until approval, then lists what was granted', async t => {
  const f = await fixture(t), account = await f.account();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-poll-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key') };
  const connected = await execute(['connect'], env), row = JSON.parse(connected.out).request;
  const before = await execute(['accounts'], env);
  assert.equal(before.code, 1); assert.match(before.err, /not_approved/);
  const raw = await execute(['request'], env);
  assert.equal(raw.code, 0, raw.err); assert.equal(JSON.parse(raw.out).request.id, row.id); assert.deepEqual(JSON.parse(raw.out).request.events, []);
  await f.request('/connect/' + row.id, { anonymous: true });
  assert.equal(JSON.parse((await execute(['request'], env)).out).request.events[0].event, 'page_opened');
  await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} });
  const denied = await execute(['accounts'], env);
  assert.equal(denied.code, 1); assert.match(denied.err, /not_approved/, 'denial is indistinguishable from waiting');
  const again = JSON.parse((await execute(['connect'], env)).out).request;
  await f.request('/api/access-requests/' + again.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: again.confirmation_code } });
  const after = await execute(['accounts'], env);
  assert.equal(after.code, 0, after.err); assert.equal(JSON.parse(after.out).accounts[0].id, account.id);
  assert.doesNotMatch(connected.out + before.err + after.out, /fdn_|google-access|refresh_token/);
});

test('--help prints the agent procedure in Japanese and, when a server is reachable, which services it offers', async t => {
  const f = await fixture(t);
  const offline = await execute(['--help'], { FOUNDATION_URL: '' });
  assert.equal(offline.code, 0, offline.err);
  assert.match(offline.out, /foundation connect --provider expo/);
  assert.match(offline.out, /verification_uri と confirmation_code/);
  assert.doesNotMatch(offline.out, /現在のサーバーで使えるサービス/);
  const online = await execute(['--help'], { FOUNDATION_URL: f.base });
  assert.equal(online.code, 0, online.err);
  assert.match(online.out, /現在のサーバーで使えるサービス: gmail \(Gmail\)/);
  assert.doesNotMatch(online.out, /foundation connect --provider expo/);
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
  const installed = await run(join(dir, 'bin', 'foundation'), ['providers'], { FOUNDATION_URL: '' });
  assert.equal(installed.code, 0, installed.err);
  assert.equal(JSON.parse(installed.out).providers[0].id, 'gmail');
});

test('FOUNDATION_AGENT gives each AI its own key file and default name; whoami and leave work through the CLI', async t => {
  const f = await fixture(t), account = await f.account();
  const home = await mkdtemp(join(tmpdir(), 'foundation-agent-home-')); t.after(() => rm(home, { recursive: true, force: true }));
  const base = { FOUNDATION_URL: f.base, HOME: home, FOUNDATION_RUNTIME_KEY_FILE: '' };
  const claude = await execute(['connect', '--purpose', 'メールの確認'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(claude.code, 0, claude.err);
  const codex = await execute(['connect', '--purpose', 'メールの確認'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(codex.code, 0, codex.err);
  const rows = [JSON.parse(claude.out).request, JSON.parse(codex.out).request];
  assert.notEqual(rows[0].id, rows[1].id);
  assert.match(rows[0].requester_name, / の claude$/); assert.match(rows[1].requester_name, / の codex$/);
  const { readdir } = await import('node:fs/promises');
  const keys = (await readdir(join(home, '.local', 'state', 'foundation'))).sort();
  assert.equal(keys.length, 2); assert.ok(keys.some(name => name.endsWith('-claude.key')) && keys.some(name => name.endsWith('-codex.key')));
  const bad = await execute(['whoami'], { ...base, FOUNDATION_AGENT: '../x' });
  assert.equal(bad.code, 1); assert.match(bad.err, /FOUNDATION_AGENT/);
  await f.request('/api/access-requests/' + rows[0].id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: rows[0].confirmation_code } });
  const who = await execute(['whoami'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(who.code, 0, who.err); assert.match(JSON.parse(who.out).agent.name, / の claude$/);
  const other = await execute(['whoami'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(other.code, 1); assert.match(other.err, /not_approved/);
  const left = await execute(['leave'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(left.code, 0, left.err); assert.match(left.out, /revoked/);
  assert.equal((await execute(['accounts'], { ...base, FOUNDATION_AGENT: 'claude' })).code, 1);
});
