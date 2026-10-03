import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, stat, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fixture, USER_A } from './helpers.mjs';
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
  for (const [name, value] of [['first input', 'google-access-personal'], ['second=入力:1', 'personal@example.test']]) {
    const saved = await f.request('/v1/resources?kind=secret&name=' + encodeURIComponent(name), { method: 'PUT', raw: value });
    assert.equal(saved.status, 200, saved.text);
  }
  return ['GOOGLE_OAUTH_ACCESS_TOKEN=first input', 'GOOGLE_ACCOUNT_EMAIL=second=入力:1'];
}

async function outputFixture(t) {
  const f = await fixture(t), runtime = await f.issueKey();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-output-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, runtime.token, { mode: 0o600 });
  return { ...f, runtime, dir, env: { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath, XDG_RUNTIME_DIR: dir } };
}

test('CLIからリテラルな名前と接続の出力を明示して、値をコマンドの環境へ渡す', async t => {
  const f = await outputFixture(t), connection = await f.connection();
  await f.keep('secret', 'token#work', 'work-value');
  const direct = await execute(['exec', 'VALUE=token#work', '--', process.execPath, '-e', "if(process.env.VALUE!=='work-value')process.exit(2);console.log('ready')"], f.env);
  assert.equal(direct.code, 0, direct.err);
  assert.equal(direct.out.trim(), 'ready');
  const used = await execute(['exec', '--inputs', JSON.stringify([{ id: connection.id, output: 'GOOGLE_ACCOUNT_EMAIL', as: 'EMAIL' }]), '--', process.execPath, '-e',
    "if(process.env.EMAIL!=='personal@example.test')process.exit(2);console.log('ready')"], f.env);
  assert.equal(used.code, 0, used.err);
  assert.equal(used.out.trim(), 'ready');
  for (const input of [{ id: connection.id, name: 'token#work', as: 'VALUE' }, { name: 'token#work', output: 'VALUE', as: 'VALUE' }, { id: connection.id, output: 'UNKNOWN' }]) {
    const refused = await execute(['exec', '--inputs', JSON.stringify([input]), '--', process.execPath, '-e', "console.log('must-not-run')"], f.env);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, '');
  }
});
const outputSpec = { name: 'signin config', as: 'AUTH_FILE', filename: 'auth.json' };

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
  const direct = await f.read('secret', (output.name), { token: f.runtime.token });
  assert.equal(direct.status, 403); assert.equal(direct.json.error.code, 'forbidden');
  const owner = await f.read('secret', output.name);
  assert.equal(owner.status, 200);
  assert.deepEqual(f.app.secrets.open(f.app.secrets.find(USER_A, output.name)), content);
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
  await f.request('/v1/resources?kind=secret&name=signin%20config', { method: 'PUT', raw: 'previous-secret' });
  const input = { name: outputSpec.name, as: 'INPUT_FILE', filename: outputSpec.filename };
  const run = await execute(['exec', '--inputs', JSON.stringify([input]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    const fs = require('node:fs');
    if (process.env.INPUT_FILE === process.env.AUTH_FILE || fs.readFileSync(process.env.INPUT_FILE, 'utf8') !== 'previous-secret') process.exit(2);
    fs.writeFileSync(process.env.AUTH_FILE, 'replacement-secret');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
  `], f.env);
  assert.equal(run.code, 0, run.err);
  for (const path of JSON.parse(run.out)) await assert.rejects(stat(dirname(path)), { code: 'ENOENT' });
  const saved = await f.read('secret', 'signin config');
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
  await f.request('/v1/principals/' + f.runtime.id, { method: 'DELETE', data: {} });
  const revoked = await execute(['exec', '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', 'console.log("must-not-run")'], f.env);
  assert.equal(revoked.code, 1); assert.match(revoked.err, /not_approved/); assert.equal(revoked.out, '');
});

test('コマンドが失敗すると一時ファイルを片づけて既存の保存値を維持する', async t => {
  const f = await outputFixture(t);
  await f.request('/v1/resources?kind=secret&name=signin%20config', { method: 'PUT', raw: 'previous-secret' });
  const input = { name: outputSpec.name, as: 'INPUT_FILE', filename: 'input' };
  const run = await execute(['exec', '--inputs', JSON.stringify([input]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    require('node:fs').writeFileSync(process.env.AUTH_FILE, 'partial-secret');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
    process.exit(7);
  `], f.env);
  assert.equal(run.code, 7);
  for (const path of JSON.parse(run.out)) await assert.rejects(stat(dirname(path)), { code: 'ENOENT' });
  assert.equal((await f.read('secret', 'signin config')).text, 'previous-secret');
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
    assert.equal((await f.read('secret', 'signin config')).status, 404);
    assert.doesNotMatch(run.out + run.err, /outside-secret|public-secret/);
  }
  assert.equal(await readFile(outside, 'utf8'), 'outside-secret');
});

test('保存に失敗したときだけ復旧用の非公開出力を残し、入力は片づける', async t => {
  const f = await outputFixture(t);
  await f.request('/v1/resources?kind=secret&name=input', { method: 'PUT', raw: 'input-secret' });
  const put = f.app.secrets.put;
  f.app.secrets.put = () => fail(503, 'storage_unavailable', 'generated-secret');
  const run = await execute(['exec', '--inputs', JSON.stringify([{ name: 'input', as: 'INPUT_FILE', filename: 'input' }]), '--output', JSON.stringify(outputSpec), '--', process.execPath, '-e', `
    require('node:fs').writeFileSync(process.env.AUTH_FILE, 'generated-secret');
    require('node:fs').writeFileSync(require('node:path').join(require('node:path').dirname(process.env.AUTH_FILE), 'unneeded-cache'), 'cache');
    console.log(JSON.stringify([process.env.INPUT_FILE, process.env.AUTH_FILE]));
  `], f.env);
  f.app.secrets.put = put;
  assert.equal(run.code, 1); assert.match(run.err, /retained for recovery/);
  assert.ok(run.err.includes('foundation keep <name> --from <file>'));
  const [inputPath, outputPath] = JSON.parse(run.out);
  assert.ok(run.err.includes(outputPath));
  await assert.rejects(stat(dirname(inputPath)), { code: 'ENOENT' });
  assert.equal((await stat(dirname(outputPath))).mode & 0o777, 0o700);
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(dirname(outputPath)), [outputSpec.filename]);
  assert.equal(await readFile(outputPath, 'utf8'), 'generated-secret');
  assert.equal((await f.read('secret', 'signin config')).status, 404);
  const retried = await execute(['keep', 'signin config', '--from', outputPath], f.env);
  assert.equal(retried.code, 0, retried.err);
  assert.equal((await f.read('secret', 'signin config')).text, 'generated-secret');
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
  assert.equal((await f.read('secret', 'signin config')).status, 404);
});

test('The runtime hands what is kept to the selected process only', async (t) => {
  const f = await fixture(t), inputs = await storedInputs(f), runtime = await f.issueKey();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-runtime-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal"||process.env.GOOGLE_ACCOUNT_EMAIL!=="personal@example.test"||process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2);console.log("runtime-ready")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'runtime-ready');
  assert.doesNotMatch(run.out + run.err, /google-access|refresh_token|fdn_/);
  await f.request('/v1/principals/' + runtime.id, { method: 'DELETE', data: {} });
  const revoked = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(revoked.code, 1);
  assert.doesNotMatch(revoked.out, /must-not-run/);
  await chmod(keyPath, 0o644);
  const unsafe = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(unsafe.code, 1);
  assert.match(unsafe.err, /private/);
});

test('init makes the key as a private file, never printing it, and the same key is used from then on', async t => {
  const f = await fixture(t), inputs = await storedInputs(f);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-pairing-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  await assert.rejects(stat(keyPath), { code: 'ENOENT' });
  const missing = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(missing.code, 1);
  assert.match(missing.err, /foundation init/);

  // init makes this machine a principal of its own; join asks a person to make it their agent.
  const started = await execute(['init', '--name', 'laptop のAI'], env);
  assert.equal(started.code, 0, started.err);
  const me = JSON.parse(started.out.slice(0, started.out.indexOf('\n\nKey file'))), secret = (await readFile(keyPath, 'utf8')).trim();
  assert.equal(me.principal.name, 'laptop のAI'); assert.deepEqual(me.acts_for, []);
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
  assert.ok(!started.out.includes(secret), 'the key stays in the file');
  assert.match(started.out, new RegExp(keyPath), 'and the agent is told where it is, for its own HTTP calls');
  const connected = await execute(['join'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out).request;
  assert.equal(row.status, 'pending'); assert.match(row.verification_uri, /\/requests\//);

  const before = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(before.code, 1); assert.match(before.err, /not_approved/);
  const approval = await f.request('/v1/requests/' + row.id + '/grant', { method: 'POST', data: { user_code: row.user_code } });
  assert.equal(approval.status, 200, approval.text);
  const run = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("connected")'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'connected');
  assert.equal((await readFile(keyPath, 'utf8')).trim(), secret, 'initialising again never replaces a key that works');
  assert.match((await execute(['join'], env)).out, /Already approved/);
  for (const result of [connected, before, run]) assert.doesNotMatch(result.out + result.err, /fdn_|google-access|refresh_token/);
});

test('CLI never overwrites or follows an existing insecure key file', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-keyfile-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const existing = join(dir, 'existing'), link = join(dir, 'link');
  await writeFile(existing, 'do-not-overwrite', { mode: 0o644 });
  let result = await execute(['init'], { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: existing });
  assert.equal(result.code, 1);
  assert.match(result.err, /private/);
  assert.equal(await readFile(existing, 'utf8'), 'do-not-overwrite');
  await symlink(existing, link);
  result = await execute(['init'], { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: link });
  assert.equal(result.code, 1);
  assert.match(result.err, /symbolic link/);
  assert.equal(await readFile(existing, 'utf8'), 'do-not-overwrite');
});

test('A denied request is indistinguishable from waiting, and asking again still works', async t => {
  const f = await fixture(t), inputs = await storedInputs(f);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-denied-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'), env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  assert.equal((await execute(['init'], env)).code, 0);
  const row = JSON.parse((await execute(['join'], env)).out).request;
  await f.request('/v1/requests/' + row.id + '/deny', { method: 'POST', data: {} });
  const denied = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], env);
  assert.equal(denied.code, 1); assert.match(denied.err, /not_approved/, 'denial is indistinguishable from waiting');
  const again = JSON.parse((await execute(['join'], env)).out).request;
  await f.request('/v1/requests/' + again.id + '/grant', { method: 'POST', data: { user_code: again.user_code } });
  const after = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("ready")'], env);
  assert.equal(after.code, 0, after.err); assert.equal(after.out.trim(), 'ready');
});

test('--helpでコマンドを案内し、認証前に接続先のOpenAPI仕様を読む', async t => {
  const f = await fixture(t);
  const help = await execute(['--help'], { FOUNDATION_URL: '' });
  assert.equal(help.code, 0, help.err);
  assert.match(help.out, /^Usage: foundation <command>/); assert.match(help.out, /api GET \/openapi.json/); assert.match(help.out, /FOUNDATION_AGENT/);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-spec-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const online = await execute(['api', 'GET', '/openapi.json'], { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'no-key') });
  assert.equal(online.code, 0, online.err);
  const published = await f.request('/openapi.json', { anonymous: true });
  assert.equal(online.out, published.text.trimEnd() + '\n');
  assert.equal(JSON.parse(online.out).paths['/v1/principals'].post.operationId, 'createPrincipal');
});

test('CLIを更新せずに接続先の新しい仕様を読み、取得失敗を失敗として返す', async t => {
  let content, status = 200;
  const server = createServer((req, res) => {
    assert.equal(req.url, '/openapi.json');
    assert.equal(req.headers.authorization, undefined, '公開仕様の取得には認証情報を送らない');
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(content);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const env = { FOUNDATION_URL: `http://127.0.0.1:${server.address().port}` };
  for (const revision of [1, 2]) {
    content = JSON.stringify({ openapi: '3.1.1', info: { version: String(revision) } });
    const result = await execute(['api', 'GET', '/openapi.json'], env);
    assert.equal(result.code, 0, result.err);
    assert.equal(result.out, content + '\n');
    assert.equal(result.err, '');
  }
  status = 503; content = JSON.stringify({ error: { code: 'unavailable', message: 'Service unavailable' } });
  const failed = await execute(['api', 'GET', '/openapi.json'], env);
  assert.equal(failed.code, 1);
  assert.deepEqual(JSON.parse(failed.out), JSON.parse(content));
});

test('The CLI installs from its npm package, and init <url> remembers the server for every later command', async t => {
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
  const unset = await run(foundation, ['api', 'GET', '/v1/principals/me'], env);
  assert.equal(unset.code, 1);
  assert.match(unset.err, /foundation init <url>/);
  const connected = await run(foundation, ['init', f.base], env);
  assert.equal(connected.code, 0, connected.err);
  assert.match(connected.out, /"principal"/);
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'config', 'foundation', 'config.json'), 'utf8')), { url: f.base });
  const spec = await run(foundation, ['api', 'GET', '/openapi.json'], env);
  assert.equal(JSON.parse(spec.out).info.title, 'Foundation API');
  const joined = await run(foundation, ['join'], env);
  assert.equal(joined.code, 0, joined.err);
  const waiting = await run(foundation, ['api', 'GET', '/v1/principals/me'], env);
  assert.match(waiting.out, /"status":"pending"/); assert.doesNotMatch(waiting.out, /fdn_/);
  const request = JSON.parse(joined.out).request;
  const approved = await f.request('/v1/requests/' + request.id + '/grant', { method: 'POST', data: { user_code: request.user_code } });
  assert.equal(approved.status, 200, approved.text);
  const me = await run(foundation, ['api', 'GET', '/v1/principals/me'], env);
  assert.equal(me.code, 0, me.out + me.err);
  const inputs = await storedInputs(f);
  const delivered = await run(foundation, ['exec', ...inputs, '--', process.execPath, '-e', 'if(process.env.GOOGLE_OAUTH_ACCESS_TOKEN!=="google-access-personal"||process.env.GOOGLE_ACCOUNT_EMAIL!=="personal@example.test")process.exit(2);console.log("package-ready")'], env);
  assert.equal(delivered.code, 0, delivered.err);
  assert.equal(delivered.out.trim(), 'package-ready');
  const output = { name: 'installed signin', as: 'NPM_CONFIG_USERCONFIG', filename: 'npmrc' };
  const saved = await run(foundation, ['exec', '--output', JSON.stringify(output), '--', process.execPath, '-e', `
    const fs = require('node:fs'), cp = require('node:child_process');
    const config = cp.execFileSync('npm', ['config', 'get', 'userconfig'], { encoding: 'utf8' }).trim();
    if (config !== process.env.NPM_CONFIG_USERCONFIG) process.exit(2);
    fs.writeFileSync(config, '//registry.npmjs.org/:_authToken=fake-install-token\\n');
    console.log('output-ready');
  `], env);
  assert.equal(saved.code, 0, saved.err);
  assert.equal(saved.out.trim(), 'output-ready');
  assert.equal((await f.read('secret', 'installed signin')).text, '//registry.npmjs.org/:_authToken=fake-install-token\n');
  assert.doesNotMatch(saved.out + saved.err, /fake-install-token/);
  const moved = await run(foundation, ['api', 'GET', '/openapi.json'], { ...env, FOUNDATION_URL: 'http://127.0.0.1:9' });
  assert.equal(moved.code, 1, 'FOUNDATION_URL wins over the remembered server');
});

test('init on a key already approved only remembers the server, and join has nothing to ask', async t => {
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-reconnect-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { HOME: join(dir, 'home'), XDG_CONFIG_HOME: join(dir, 'config'), FOUNDATION_URL: '', FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'key') };
  await writeFile(env.FOUNDATION_RUNTIME_KEY_FILE, (await f.issueKey()).token, { mode: 0o600 });
  const again = await execute(['init', f.base], env);
  assert.equal(again.code, 0, again.err);
  assert.match(again.out, /"acts_for": \[\n\s+"/);
  assert.match((await execute(['join'], env)).out, /Already approved/);
  const me = await execute(['api', 'GET', '/v1/principals/me'], env);
  assert.equal(me.code, 0, me.out + me.err);
});

test('FOUNDATION_AGENT gives each agent its own key file and default name', async t => {
  const f = await fixture(t), inputs = await storedInputs(f);
  const home = await mkdtemp(join(tmpdir(), 'foundation-agent-home-')); t.after(() => rm(home, { recursive: true, force: true }));
  const base = { FOUNDATION_URL: f.base, HOME: home, FOUNDATION_RUNTIME_KEY_FILE: '' };
  assert.equal((await execute(['init'], { ...base, FOUNDATION_AGENT: 'claude' })).code, 0);
  const first = await execute(['join'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(first.code, 0, first.err);
  assert.equal((await execute(['init'], { ...base, FOUNDATION_AGENT: 'codex' })).code, 0);
  const second = await execute(['join'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(second.code, 0, second.err);
  const rows = [first, second].map(result => JSON.parse(result.out).request);
  assert.notEqual(rows[0].id, rows[1].id);
  assert.match(rows[0].requester_name, / の claude$/); assert.match(rows[1].requester_name, / の codex$/);
  const { readdir } = await import('node:fs/promises');
  const keys = (await readdir(join(home, '.local', 'state', 'foundation'))).sort();
  assert.equal(keys.length, 2); assert.ok(keys.some(name => name.endsWith('-claude.key')) && keys.some(name => name.endsWith('-codex.key')));
  const bad = await execute(['init'], { ...base, FOUNDATION_AGENT: '../x' });
  assert.equal(bad.code, 1); assert.match(bad.err, /FOUNDATION_AGENT/);
  await f.request('/v1/requests/' + rows[0].id + '/grant', { method: 'POST', data: { user_code: rows[0].user_code } });
  const approved = await execute(['exec', ...inputs, '--', process.execPath, '-e', 'console.log("ready")'], { ...base, FOUNDATION_AGENT: 'claude' });
  assert.equal(approved.code, 0, approved.err);
  const other = await execute(['exec', ...inputs, '--', process.execPath, '-e', '0'], { ...base, FOUNDATION_AGENT: 'codex' });
  assert.equal(other.code, 1); assert.match(other.err, /not_approved/, 'each key is approved on its own');
});

test('アクセスキーの鍵ファイルを持つAIは、次に動いたときにWebAuthnの資格情報へ移り、鍵ファイルには秘密鍵だけが残る', async t => {
  const f = await outputFixture(t), before = await readFile(f.env.FOUNDATION_RUNTIME_KEY_FILE, 'utf8');
  const run = await execute(['api', 'GET', '/v1/principals/me'], f.env);
  assert.equal(run.code, 0, run.err);
  assert.equal(JSON.parse(run.out).principal.id, f.runtime.id);
  const after = JSON.parse(await readFile(f.env.FOUNDATION_RUNTIME_KEY_FILE, 'utf8'));
  assert.equal(after.webauthn_credential.private_key.kty, 'EC');
  assert.ok(!JSON.stringify(after).includes(before.trim()), 'the access key is no longer kept in the file');
  assert.equal((await stat(f.env.FOUNDATION_RUNTIME_KEY_FILE)).mode & 0o777, 0o600);
  const credentials = (await f.request('/v1/credentials?as=' + f.runtime.id, { anonymous: true, token: f.runtime.token })).json.credentials.filter(item => item.kind === 'webauthn');
  assert.deepEqual(credentials.map(item => item.id), [after.webauthn_credential.id]);
  assert.equal(JSON.parse((await execute(['api', 'GET', '/v1/principals/me'], f.env)).out).principal.id, f.runtime.id, 'and the credential is what proves it from then on');
});

test('tokenはWebAuthnの資格情報で証明して1時間のトークンを出し、それでAPIをそのAIとして呼べる', async t => {
  const f = await outputFixture(t);
  const printed = await execute(['token'], f.env);
  assert.equal(printed.code, 0, printed.err);
  const me = await f.request('/v1/principals/me', { anonymous: true, token: printed.out.trim() });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.principal.id, f.runtime.id);
});

test('渡された封筒のあるシークレットは、Foundation が開けなくても、この機械が自分の鍵で開けてコマンドに渡す', async t => {
  const { seal, open } = await import('../cli/envelope.mjs');
  const { USER_A } = await import('./helpers.mjs');
  const f = await fixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-handed-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'key') };
  const started = await execute(['init', '--name', 'reader'], env);
  assert.equal(started.code, 0, started.err);
  const machine = JSON.parse(started.out.slice(0, started.out.indexOf('\n\nKey file'))).principal;
  const asked = JSON.parse((await execute(['join'], env)).out).request;
  assert.equal((await f.request('/v1/requests/' + asked.id + '/grant', { method: 'POST', data: { user_code: asked.user_code } })).status, 200);
  // The owner keeps a secret that only they can open: Foundation is not their agent, and holds no envelope for it.
  const kept = (await f.keep('secret', 'handed/token', 'opened-here')).json.resource;
  assert.equal((await f.request('/v1/relations', { method: 'DELETE', data: { subject: f.app.keys.agentId, relation: 'agent', object_type: 'principal', object_id: USER_A } })).status, 200);
  await f.request('/v1/resources/' + kept.id + '/envelopes/' + f.app.keys.agentId, { method: 'DELETE', data: {} });
  const refused = await execute(['exec', 'TOKEN=handed/token', '--', process.execPath, '-e', '0'], env);
  assert.equal(refused.code, 1, 'nobody who may hand it over can open it');
  // Handing it to the machine: a line to see it, and its key sealed for the machine's own.
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: machine.id, relation: 'viewer', object_type: 'resource', object_id: kept.id } })).status, 201);
  const mine = await f.request('/v1/resources/' + kept.id + '/content');
  const contentKey = open(Buffer.from(mine.json.envelope, 'base64url'), (await f.keyOf({})).privateKey);
  const theirs = (await f.request('/v1/principals/' + machine.id + '/public-key')).json.key.public_key;
  const handed = await f.request('/v1/resources/' + kept.id + '/envelopes/' + machine.id, { method: 'PUT', data: { wrapped: seal(contentKey, Buffer.from(theirs, 'base64url')).toString('base64url') } });
  assert.equal(handed.status, 200, handed.text);
  const run = await execute(['exec', 'TOKEN=handed/token', '--', process.execPath, '-e', 'process.stdout.write(process.env.TOKEN)'], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out, 'opened-here');
  const asFile = await execute(['exec', '--inputs', JSON.stringify([{ name: 'handed/token', as: 'TOKEN_FILE', filename: 'token.txt' }]), '--', process.execPath, '-e', 'process.stdout.write(require("fs").readFileSync(process.env.TOKEN_FILE, "utf8"))'], env);
  assert.equal(asFile.code, 0, asFile.err);
  assert.equal(asFile.out, 'opened-here');
  assert.equal(JSON.parse(await readFile(env.FOUNDATION_RUNTIME_KEY_FILE, 'utf8')).key.private_key.length, 43, 'opened with the key this machine keeps');
});
