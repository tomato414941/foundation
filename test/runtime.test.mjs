import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, readdir, stat, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fixture } from './helpers.mjs';
import { fail } from '../src/errors.mjs';

const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['cli/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', (part) => { out += part; }); child.stderr.on('data', (part) => { err += part; });
  child.once('error', reject); child.once('exit', (code) => resolve({ code, out, err }));
});

// The runtime is only what the agent cannot do for itself: make the key, and put what is kept into a command.
// Everything else it does over HTTP, with the key in that file.
async function storedInputs(f) {
  for (const [name, value] of [['first input', 'google-access-personal-readonly'], ['second=入力:1', 'personal@example.test']]) {
    const saved = await f.request('/api/secrets?name=' + encodeURIComponent(name), { method: 'PUT', raw: value });
    assert.equal(saved.status, 200, saved.text);
  }
  return ['GOOGLE_OAUTH_ACCESS_TOKEN=first input', 'GMAIL_ACCOUNT_EMAIL=second=入力:1'];
}

async function outputFixture(t) {
  const f = await fixture(t), runtime = await f.issueKey();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-output-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, runtime.token, { mode: 0o600 });
  return { ...f, runtime, dir, env: { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath, XDG_RUNTIME_DIR: dir } };
}
const outputSpec = { name: 'login config', as: 'AUTH_FILE', filename: 'auth.json' };

test('コマンドが作った非公開ファイルを名前どおりに保存し、後のコマンドへ渡す', async t => {
  const f = await outputFixture(t);
  const output = { ...outputSpec, name: '  a/aa=入力 &?#+ % ..  ' }, content = Buffer.from([0, 1, 2, 255, 10, 13, 42]);
  const run = await execute(['exec', '--output', JSON.stringify(output), '--', process.execPath, '-e', `
    const fs = require('node:fs'), path = require('node:path'), target = process.env.AUTH_FILE;
    if ((fs.statSync(target).mode & 0o777) !== 0o600 || (fs.statSync(path.dirname(target)).mode & 0o777) !== 0o700) process.exit(2);
    if (process.env.FOUNDATION_RUNTIME_KEY_FILE || process.env.FOUNDATION_NAMES !== '[]') process.exit(3);
    fs.writeFileSync(target, Buffer.from('${content.toString('base64')}', 'base64'));
    console.log(target);
  `], f.env);
  assert.equal(run.code, 0, run.err);
  assert.match(run.err, /Saved output as/);
  await assert.rejects(stat(dirname(run.out.trim())), { code: 'ENOENT' });
  const direct = await f.request('/v1/secrets?name=' + encodeURIComponent(output.name), { token: f.runtime.token });
  assert.equal(direct.status, 403); assert.equal(direct.json.error.code, 'write_only');
  const owner = await fetch(f.base + '/api/secrets?name=' + encodeURIComponent(output.name), { headers: { cookie: f.cookie() } });
  assert.equal(owner.status, 200);
  assert.deepEqual(Buffer.from(await owner.arrayBuffer()), content);
  const used = await execute(['exec', '--inputs', JSON.stringify([output]), '--', process.execPath, '-e', `
    const fs = require('node:fs');
    if (!fs.readFileSync(process.env.AUTH_FILE).equals(Buffer.from('${content.toString('base64')}', 'base64'))) process.exit(2);
    console.log(process.env.AUTH_FILE);
  `], f.env);
  assert.equal(used.code, 0, used.err);
  await assert.rejects(stat(dirname(used.out.trim())), { code: 'ENOENT' });
  assert.ok(!(run.out + run.err + used.out + used.err).includes(content.toString('base64')));
});

test('入力ファイルと出力ファイルを別々に渡し、成功した出力で指定した値を置き換える', async t => {
  const f = await outputFixture(t);
  await f.request('/api/secrets?name=login%20config', { method: 'PUT', raw: 'previous-secret' });
  const input = { name: outputSpec.name, as: 'INPUT_FILE', filename: outputSpec.filename };
  const run = await execute(['exec', '--inputs', JSON.stringify([input]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    const fs = require('node:fs');
    if (process.env.INPUT_FILE === process.env.AUTH_FILE || fs.readFileSync(process.env.INPUT_FILE, 'utf8') !== 'previous-secret') process.exit(2);
    fs.writeFileSync(process.env.AUTH_FILE, 'replacement-secret');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
  `], f.env);
  assert.equal(run.code, 0, run.err);
  for (const path of JSON.parse(run.out)) await assert.rejects(stat(dirname(path)), { code: 'ENOENT' });
  const saved = await f.request('/api/secrets?name=login%20config');
  assert.equal(saved.text, 'replacement-secret');
  assert.doesNotMatch(run.out + run.err, /previous-secret|replacement-secret/);
});

test('出力指定とFoundationの承認を確認してからコマンドを実行する', async t => {
  const f = await outputFixture(t);
  for (const output of [null, [], { ...outputSpec, name: '' }, { ...outputSpec, name: 'a\nb' }, { ...outputSpec, name: '\ud800' },
    { ...outputSpec, name: 'a'.repeat(201) }, { ...outputSpec, as: 'PATH' }, { ...outputSpec, filename: '../auth' }, { ...outputSpec, secret: false }]) {
    const run = await execute(['exec', '--output', JSON.stringify(output), '--', process.execPath, '-e', 'console.log("must-not-run")'], f.env);
    assert.equal(run.code, 1, JSON.stringify(output)); assert.equal(run.out, '');
  }
  const collision = await execute(['exec', 'AUTH_FILE=anything', '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', 'console.log("must-not-run")'], f.env);
  assert.equal(collision.code, 1); assert.match(collision.err, /different environment variable/); assert.equal(collision.out, '');
  await f.request('/api/keys/' + f.runtime.id, { method: 'DELETE' });
  const revoked = await execute(['exec', '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', 'console.log("must-not-run")'], f.env);
  assert.equal(revoked.code, 1); assert.match(revoked.err, /not_approved/); assert.equal(revoked.out, '');
});

test('コマンドが失敗すると一時ファイルを片づけて既存の保存値を維持する', async t => {
  const f = await outputFixture(t);
  await f.request('/api/secrets?name=login%20config', { method: 'PUT', raw: 'previous-secret' });
  const input = { name: outputSpec.name, as: 'INPUT_FILE', filename: 'input' };
  const run = await execute(['exec', '--inputs', JSON.stringify([input]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    require('node:fs').writeFileSync(process.env.AUTH_FILE, 'partial-secret');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
    process.exit(7);
  `], f.env);
  assert.equal(run.code, 7);
  for (const path of JSON.parse(run.out)) await assert.rejects(stat(dirname(path)), { code: 'ENOENT' });
  assert.equal((await f.request('/api/secrets?name=login%20config')).text, 'previous-secret');
  assert.doesNotMatch(run.out + run.err, /partial-secret|previous-secret/);
});

test('空・過大・公開・リンク・特殊ファイルの出力を安全に拒否する', async t => {
  const f = await outputFixture(t), outside = join(f.dir, 'outside');
  await writeFile(outside, 'outside-secret', { mode: 0o600 });
  const cases = [
    ['', /1 byte to 1MB/],
    ['fs.writeFileSync(p, Buffer.alloc(1024 * 1024 + 1))', /1 byte to 1MB/],
    ['fs.writeFileSync(p, "public-secret"); fs.chmodSync(p, 0o644)', /private regular file/],
    ['fs.writeFileSync(p, "public-secret"); fs.chmodSync(require("node:path").dirname(p), 0o755)', /directory must stay private/],
    ['fs.unlinkSync(p)', /did not create/],
    [`fs.unlinkSync(p); fs.symlinkSync(${JSON.stringify(outside)}, p)`, /symbolic link/],
    [`fs.unlinkSync(p); fs.linkSync(${JSON.stringify(outside)}, p)`, /private regular file/],
    ['fs.unlinkSync(p); fs.mkdirSync(p)', /private regular file/],
    ['fs.unlinkSync(p); require("node:child_process").execFileSync("mkfifo", [p])', /private regular file/],
  ];
  for (const [script, expected] of cases) {
    const run = await execute(['exec', '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `const fs = require('node:fs'), p = process.env.AUTH_FILE; console.log(p); ${script}`], f.env);
    assert.equal(run.code, 1, run.err); assert.match(run.err, expected);
    await assert.rejects(stat(dirname(run.out.trim())), { code: 'ENOENT' });
    assert.equal((await f.request('/api/secrets?name=login%20config')).status, 404);
    assert.doesNotMatch(run.out + run.err, /outside-secret|public-secret/);
  }
  assert.equal(await readFile(outside, 'utf8'), 'outside-secret');
});

test('保存に失敗したときだけ復旧用の非公開出力を残し、入力は片づける', async t => {
  const f = await outputFixture(t);
  await f.request('/api/secrets?name=input', { method: 'PUT', raw: 'input-secret' });
  const put = f.app.store.writeSecret;
  f.app.store.writeSecret = () => fail(503, 'storage_unavailable', 'generated-secret');
  const run = await execute(['exec', '--inputs', JSON.stringify([{ name: 'input', as: 'INPUT_FILE', filename: 'input' }]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    require('node:fs').writeFileSync(process.env.AUTH_FILE, 'generated-secret');
    require('node:fs').writeFileSync(require('node:path').join(require('node:path').dirname(process.env.AUTH_FILE), 'unneeded-cache'), 'cache');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
  `], f.env);
  f.app.store.writeSecret = put;
  assert.equal(run.code, 1); assert.match(run.err, /retained for recovery/);
  const [inputPath, outputPath] = JSON.parse(run.out);
  assert.ok(run.err.includes(outputPath));
  await assert.rejects(stat(dirname(inputPath)), { code: 'ENOENT' });
  assert.equal((await stat(dirname(outputPath))).mode & 0o777, 0o700);
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(dirname(outputPath)), [outputSpec.filename]);
  assert.equal(await readFile(outputPath, 'utf8'), 'generated-secret');
  assert.equal((await f.request('/api/secrets?name=login%20config')).status, 404);
  const retried = await execute(['api', 'PUT', '/v1/secrets?name=login%20config&secret=true', '--from', outputPath], f.env);
  assert.equal(retried.code, 0, retried.err);
  assert.equal((await f.request('/api/secrets?name=login%20config')).text, 'generated-secret');
  assert.doesNotMatch(run.out + run.err + retried.out + retried.err, /generated-secret|input-secret/);
});

test('中断を子プロセスに伝えて一時ファイルを片づけ、途中の出力を保存しない', async t => {
  const f = await outputFixture(t);
  const child = spawn(process.execPath, ['cli/runtime.mjs', 'exec', '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    process.on('SIGTERM', () => { console.error('interrupted'); process.exit(0); });
    require('node:fs').writeFileSync(process.env.AUTH_FILE, 'partial-secret');
    console.log(process.env.AUTH_FILE);
    setInterval(() => {}, 1000);
  `], { env: { ...process.env, ...f.env } });
  t.after(() => child.kill('SIGKILL'));
  let out = '', err = '';
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  child.stderr.on('data', part => { err += part; });
  await new Promise(resolve => child.stdout.on('data', part => { out += part; if (out.includes('\n')) resolve(); }));
  child.kill('SIGTERM');
  assert.equal(await done, 1);
  assert.match(err, /interrupted/);
  await assert.rejects(stat(dirname(out.trim())), { code: 'ENOENT' });
  assert.equal((await f.request('/api/secrets?name=login%20config')).status, 404);
});

test('The runtime hands what is kept to the selected process only', async (t) => {
  const f = await fixture(t), inputs = await storedInputs(f), runtime = await f.issueKey();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-runtime-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal-readonly"||process.env.GMAIL_ACCOUNT_EMAIL!=="personal@example.test"||process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2);console.log("runtime-ready")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'runtime-ready');
  assert.doesNotMatch(run.out + run.err, /google-access|refresh_token|fdn_/);
  await f.request('/api/keys/' + runtime.id, { method: 'DELETE' });
  const revoked = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(revoked.code, 1);
  assert.doesNotMatch(revoked.out, /must-not-run/);
  await chmod(keyPath, 0o644);
  const unsafe = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(unsafe.code, 1);
  assert.match(unsafe.err, /private/);
});

test('connect makes the key as a private file, never printing it, and the same key is used from then on', async t => {
  const f = await fixture(t), inputs = await storedInputs(f);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-pairing-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  await assert.rejects(stat(keyPath), { code: 'ENOENT' });
  const missing = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(missing.code, 1);
  assert.match(missing.err, /connect/);

  const connected = await execute(['connect', '--name', 'dev-us のAI'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out.slice(0, connected.out.indexOf('\n\nKey file'))).request, secret = (await readFile(keyPath, 'utf8')).trim();
  assert.equal(row.status, 'pending'); assert.match(row.verification_uri, /\/keys\//);
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
  assert.ok(!connected.out.includes(secret), 'the key stays in the file');
  assert.match(connected.out, new RegExp(keyPath), 'and the agent is told where it is, for its own HTTP calls');

  const before = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(before.code, 1); assert.match(before.err, /not_approved/);
  const approval = await f.request('/api/key-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } });
  assert.equal(approval.status, 200, approval.text);
  const run = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("connected")'], env);
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
  const f = await fixture(t), inputs = await storedInputs(f);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-denied-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const row = JSON.parse((await execute(['connect'], env)).out.split('\n\nKey file')[0]).request;
  await f.request('/api/key-requests/' + row.id + '/deny', { method: 'POST', data: {} });
  const denied = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(denied.code, 1); assert.match(denied.err, /not_approved/, 'denial is indistinguishable from waiting');
  const again = JSON.parse((await execute(['connect'], env)).out.split('\n\nKey file')[0]).request;
  await f.request('/api/key-requests/' + again.id + '/approve', { method: 'POST', data: { confirmationCode: again.confirmation_code } });
  const after = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("ready")'], env);
  assert.equal(after.code, 0, after.err); assert.equal(after.out.trim(), 'ready');
});

test('--help describes the API, and when a server is reachable, what it can obtain itself', async t => {
  const f = await fixture(t);
  const offline = await execute(['--help'], { FOUNDATION_URL: '', XDG_CONFIG_HOME: join(tmpdir(), 'foundation-no-config') });
  assert.equal(offline.code, 0, offline.err);
  assert.match(offline.out, /GET \/v1\/adapters lists what this server can obtain itself/);
  assert.match(offline.out, /Nothing here needs a shell/);
  assert.doesNotMatch(offline.out, /gmail/);
  const online = await execute(['--help'], { FOUNDATION_URL: f.base });
  assert.equal(online.code, 0, online.err);
  assert.match(online.out, /gmail.readonly  Gmail \/ メールの読み取り  outputs: GOOGLE_OAUTH_ACCESS_TOKEN/);
});

test('The CLI installs from its npm package, and connect <url> remembers the server for every later command', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-install-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const run = (command, args, env = {}) => new Promise((resolve) => {
    const child = spawn(command, args, { env: { ...process.env, npm_config_cache: join(dir, 'npm-cache'), npm_config_update_notifier: 'false', ...env } });
    let out = '', err = ''; child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('exit', code => resolve({ code, out, err }));
  });
  const packed = await run('npm', ['pack', '--pack-destination', dir, './cli']);
  assert.equal(packed.code, 0, packed.err);
  const install = await run('npm', ['install', '--global', '--offline', '--prefix', join(dir, 'global'), join(dir, packed.out.trim().split('\n').at(-1))]);
  assert.equal(install.code, 0, install.err);
  const foundation = join(dir, 'global', 'bin', 'foundation');
  const env = { HOME: join(dir, 'home'), XDG_CONFIG_HOME: join(dir, 'config'), FOUNDATION_URL: '', FOUNDATION_RUNTIME_KEY_FILE: '' };
  const version = await run(foundation, ['--version'], env);
  assert.equal(version.out.trim(), JSON.parse(await readFile('cli/package.json', 'utf8')).version);
  const unset = await run(foundation, ['api', 'GET', '/v1/me'], env);
  assert.equal(unset.code, 1);
  assert.match(unset.err, /foundation connect <url>/);
  const connected = await run(foundation, ['connect', f.base], env);
  assert.equal(connected.code, 0, connected.err);
  assert.match(connected.out, /confirmation_code/);
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'config', 'foundation', 'config.json'), 'utf8')), { url: f.base });
  const help = await run(foundation, ['--help'], env);
  assert.match(help.out, /gmail.readonly/);
  const waiting = await run(foundation, ['api', 'GET', '/v1/me'], env);
  assert.match(waiting.out, /not_approved/);
  const request = JSON.parse(connected.out.split('\n\nKey file')[0]).request;
  const approved = await f.request('/api/key-requests/' + request.id + '/approve', { method: 'POST', data: { confirmationCode: request.confirmation_code } });
  assert.equal(approved.status, 200, approved.text);
  const me = await run(foundation, ['api', 'GET', '/v1/me'], env);
  assert.equal(me.code, 0, me.out + me.err);
  const inputs = await storedInputs(f);
  const delivered = await run(foundation, ['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal-readonly"||process.env.GMAIL_ACCOUNT_EMAIL!=="personal@example.test")process.exit(2);console.log("package-ready")'], env);
  assert.equal(delivered.code, 0, delivered.err);
  assert.equal(delivered.out.trim(), 'package-ready');
  const output = { name: 'installed login', as: 'NPM_CONFIG_USERCONFIG', filename: 'npmrc' };
  const saved = await run(foundation, ['exec', '--output', JSON.stringify(output), '--', process.execPath, '-e', `
    const fs = require('node:fs'), cp = require('node:child_process');
    const config = cp.execFileSync('npm', ['config', 'get', 'userconfig'], { encoding: 'utf8' }).trim();
    if (config !== process.env.NPM_CONFIG_USERCONFIG) process.exit(2);
    fs.writeFileSync(config, '//registry.npmjs.org/:_authToken=fake-install-token\\n');
    console.log('output-ready');
  `], env);
  assert.equal(saved.code, 0, saved.err);
  assert.equal(saved.out.trim(), 'output-ready');
  assert.equal((await f.request('/api/secrets?name=installed%20login')).text, '//registry.npmjs.org/:_authToken=fake-install-token\n');
  assert.doesNotMatch(saved.out + saved.err, /fake-install-token/);
  const moved = await run(foundation, ['--help'], { ...env, FOUNDATION_URL: 'http://127.0.0.1:9' });
  assert.doesNotMatch(moved.out, /gmail.readonly/, 'FOUNDATION_URL wins over the remembered server');
});

test('connect on a key already approved only remembers the server', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-reconnect-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { HOME: join(dir, 'home'), XDG_CONFIG_HOME: join(dir, 'config'), FOUNDATION_URL: '', FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'key') };
  await writeFile(env.FOUNDATION_RUNTIME_KEY_FILE, (await f.issueKey()).token, { mode: 0o600 });
  const again = await execute(['connect', f.base], env);
  assert.equal(again.code, 0, again.err);
  assert.match(again.out, /Already approved/);
  const me = await execute(['api', 'GET', '/v1/me'], env);
  assert.equal(me.code, 0, me.out + me.err);
});

test('FOUNDATION_AGENT gives each agent its own key file and default name', async t => {
  const f = await fixture(t), inputs = await storedInputs(f);
  const home = await mkdtemp(join(tmpdir(), 'foundation-agent-home-')); t.after(() => rm(home, { recursive: true, force: true }));
  const base = { FOUNDATION_URL: f.base, HOME: home, FOUNDATION_RUNTIME_KEY_FILE: '' };
  const first = await execute(['connect'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(first.code, 0, first.err);
  const second = await execute(['connect'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(second.code, 0, second.err);
  const rows = [first, second].map(result => JSON.parse(result.out.split('\n\nKey file')[0]).request);
  assert.notEqual(rows[0].id, rows[1].id);
  assert.match(rows[0].name, / の claude$/); assert.match(rows[1].name, / の codex$/);
  const { readdir } = await import('node:fs/promises');
  const keys = (await readdir(join(home, '.local', 'state', 'foundation'))).sort();
  assert.equal(keys.length, 2); assert.ok(keys.some(name => name.endsWith('-claude.key')) && keys.some(name => name.endsWith('-codex.key')));
  const bad = await execute(['connect'], { ...base, FOUNDATION_AGENT: '../x' });
  assert.equal(bad.code, 1); assert.match(bad.err, /FOUNDATION_AGENT/);
  await f.request('/api/key-requests/' + rows[0].id + '/approve', { method: 'POST', data: { confirmationCode: rows[0].confirmation_code } });
  const approved = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("ready")'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(approved.code, 0, approved.err);
  const other = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(other.code, 1); assert.match(other.err, /not_approved/, 'each key is approved on its own');
});
