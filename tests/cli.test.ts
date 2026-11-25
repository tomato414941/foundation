import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { enroll, fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Redactor, secretVariants } from '../cli/src/execute.js';
import { encode, newIdentityKeys, publicPart, seal, wrap } from '../shared/encryption.js';
import { sealItem } from '../shared/custody.js';
import { CustodyClient } from '../shared/client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { OperationClient } from '../shared/operation-client.js';

async function cliFixture(environmentOverrides: Record<string, string> = {}, bundleDirectory = resolve('cli/dist')) {
  const reserved = createServer();
  await new Promise<void>(resolve => reserved.listen(0, '127.0.0.1', resolve));
  const port = (reserved.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => reserved.close(error => error ? reject(error) : resolve()));
  const f = await fixture({ FOUNDATION_ORIGIN: 'http://127.0.0.1:' + port }),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  const origin = await app.listen({ host: '127.0.0.1', port }),
    directory = await mkdtemp(join(tmpdir(), 'foundation-cli-test-'));
  const environment = { ...process.env, XDG_CONFIG_HOME: directory, ...environmentOverrides };
  for (const key of [
    'FOUNDATION_ORIGIN',
    'FOUNDATION_TOKEN',
    'FOUNDATION_PRINCIPAL_ID',
    'FOUNDATION_PRIVATE_KEY',
    'FOUNDATION_PRIVATE_KEYS',
    'FOUNDATION_KEY_BINDING',
  ])
    delete environment[key];
  async function run(args: string[], input?: string, extraEnvironment: Record<string, string> = {}) {
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveResult, reject) => {
      const child = spawn(process.execPath, [resolve(bundleDirectory, 'cli.mjs'), ...args], {
        env: { ...environment, ...extraEnvironment },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '',
        stderr = '';
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
      });
      child.stderr.on('data', (chunk) => {
        stderr += chunk;
      });
      child.once('error', reject);
      child.once('close', (code) => resolveResult({ code, stdout, stderr }));
      child.stdin.end(input);
    });
  }
  // Start a command and resolve as soon as its stderr matches, keeping the finished promise.
  // Commands still running when a test ends, which closing the fixture stops even if the test failed while they waited.
  const running = new Set<Promise<unknown> & { stop(): void }>();
  function start(args: string[], until: RegExp) {
    const child = spawn(process.execPath, [resolve(bundleDirectory, 'cli.mjs'), ...args], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    const finished = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveResult) =>
      child.once('close', (code) => resolveResult({ code, stdout, stderr })));
    const tracked = Object.assign(finished.then(() => running.delete(tracked)), { stop: () => child.kill('SIGTERM') });
    running.add(tracked);
    const shown = new Promise<string>((resolveShown) =>
      child.stderr.on('data', (chunk) => { stderr += chunk; if (until.test(stderr)) resolveShown(stderr); }));
    child.stdin.end();
    return { shown, finished };
  }
  async function close() {
    for (const command of running) command.stop();
    await Promise.all(running);
    await app.close();
    await f.close();
    await rm(directory, { recursive: true, force: true });
  }
  async function person(name: string) {
    const identityKeys = await newIdentityKeys();
    const { keys: _keys, ...enrolled } = await enroll(f.authentication, name, identityKeys);
    const actor = (await f.authentication.authenticate(enrolled.token))!;
    return { ...enrolled, actor, keys: { ...identityKeys, publicKey: publicPart(identityKeys.encryption), privateKey: identityKeys.encryption } };
  }
  return { f, context, app, origin, directory, run, start, close, person };
}

test('CLIで登録して変数を保存し、コマンドへ渡して出力を伏せ、値を開いて書き出す', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const initialized = await c.run(['init', '--name', 'CLI test', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const identityPath = join(c.directory, 'foundation', 'identity.json');
  assert.equal((await stat(identityPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(c.directory, 'foundation'))).mode & 0o777, 0o700);
  const kept = await c.run(['keep', 'CLI variable', '--stdin'], '変数-value/123');
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  assert.equal(resource.kind, 'variable');
  assert.equal(resource.data.bytes, 16);
  const output = join(c.directory, 'revealed.txt'),
    read = await c.run(['read', resource.id, '--output', output]);
  assert.equal(read.code, 0, read.stderr);
  assert.equal(await readFile(output, 'utf8'), '変数-value/123');
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  const fileRecord = join(c.directory, 'file-path');
  const inputs = JSON.stringify([
    { name: 'TEST_VALUE', source: { id: resource.id } },
    { name: 'TEST_FILE', source: { id: resource.id }, format: 'file' },
  ]);
  const command =
    "const fs=require('node:fs');fs.writeFileSync(process.argv[1],process.env.TEST_FILE);process.stdout.write(process.env.TEST_VALUE+'|'+fs.readFileSync(process.env.TEST_FILE)+'|'+(fs.statSync(process.env.TEST_FILE).mode&511));process.stderr.write(Buffer.from(process.env.TEST_VALUE).toString('base64'));";
  const executed = await c.run([
    'exec',
    '--inputs',
    inputs,
    '--',
    process.execPath,
    '-e',
    command,
    fileRecord,
  ]);
  assert.equal(executed.code, 0, executed.stderr);
  assert.equal(executed.stdout, '[redacted]|[redacted]|384');
  assert.equal(executed.stderr, '[redacted]');
  const temporary = await readFile(fileRecord, 'utf8');
  await assert.rejects(() => stat(temporary), { code: 'ENOENT' });
  const principalId = JSON.parse(initialized.stdout).principal.id;
  const exported = join(c.directory, 'export.ndjson'),
    exportResult = await c.run(['api', 'GET', '/api/principals/' + principalId + '/export', '--output', exported]);
  assert.equal(exportResult.code, 0, exportResult.stderr);
  assert.equal((await stat(exported)).mode & 0o777, 0o600);
  assert.ok((await readFile(exported, 'utf8')).includes('CLI variable'));
  const exportedResource = (await readFile(exported, 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    .find(item => item.type === 'resource');
  assert.equal(exportedResource.resource.id, resource.id);
  assert.equal(exportedResource.custody.revision, 1);
  const opened = join(c.directory, 'opened.ndjson'), openedResult = await c.run(['export', '--output', opened]);
  assert.equal(openedResult.code, 0, openedResult.stderr);
  assert.deepEqual(JSON.parse(openedResult.stdout), { path: opened, sealed: [] });
  assert.equal((await stat(opened)).mode & 0o777, 0o600);
  const entries = (await readFile(opened, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual([entries[0].format, entries[0].version], ['foundation', 6]);
  const openedResource = entries.find(item => item.type === 'resource');
  assert.equal(openedResource.custody, undefined);
  assert.equal(Buffer.from(openedResource.content, 'base64').toString('utf8'), '変数-value/123');
});

test('CLIは保存した複数の身元から既定の身元を切り替え、コマンドごとに指定した身元で実行する', async t => {
  const c = await cliFixture();
  t.after(c.close);
  const first = JSON.parse((await c.run(['init', '--name', 'first-agent', '--origin', c.origin])).stdout).principal,
    second = JSON.parse((await c.run(['init', '--name', 'second-agent', '--origin', c.origin])).stdout).principal;
  const principalOf = async (args: string[], environment: Record<string, string> = {}) =>
    JSON.parse((await c.run(['status', ...args], undefined, environment)).stdout).principal.id;
  const listed = JSON.parse((await c.run(['identity', 'list'])).stdout);
  assert.deepEqual(listed.map((item: { name: string; current: boolean }) => [item.name, item.current]),
    [['first-agent', false], ['second-agent', true]]);
  assert.equal(await principalOf([]), second.id);
  assert.equal(await principalOf(['--principal', first.id]), first.id);
  assert.equal(await principalOf([], { FOUNDATION_PRINCIPAL_ID: first.id }), first.id);
  assert.equal((await c.run(['identity', 'use', first.id])).code, 0);
  assert.equal(await principalOf([]), first.id);
  assert.equal(await principalOf(['--principal', second.id]), second.id);
  const unknown = await c.run(['status', '--principal', randomUUID()]);
  assert.notEqual(unknown.code, 0);
  assert.match(unknown.stderr, /No saved identity has principal/);
});

test('CLIの確認コードを承認し、同じAPIから所有者のリソースを利用する', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const owner = await c.person('Human owner');
  const initialized = await c.run(['init', '--name', 'Joining machine', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const joined = await c.run(['request-access']);
  assert.equal(joined.code, 0, joined.stderr);
  const request = JSON.parse(joined.stdout);
  assert.match(request.code, /^[A-Z0-9]{8}$/);
  assert.equal(request.canAnswer, false);
  const approved = await c.app.inject({
    method: 'POST',
    url: '/api/requests/' + request.id + '/approve',
    headers: { authorization: 'Bearer ' + owner.token },
    payload: { code: request.code },
  });
  assert.equal(approved.statusCode, 200, approved.body);
  const answered = await c.run(['api', 'GET', '/api/requests/' + request.id]);
  assert.equal(answered.code, 0, answered.stderr);
  assert.equal(JSON.parse(answered.stdout).state, 'approved');
  const status = await c.run(['status']);
  assert.equal(status.code, 0, status.stderr);
  assert.ok(JSON.parse(status.stdout).principals.some((item: { id: string }) => item.id === owner.actor.id));
  const kept = await c.run(
    ['keep', 'Owner variable', '--owner', owner.actor.id, '--stdin'],
    'delegated-value',
  );
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  const used = await c.run([
    'exec',
    '--inputs',
    JSON.stringify([{ name: 'TEST_VALUE', source: { id: resource.id } }]),
    '--',
    process.execPath,
    '-e',
    'process.stdout.write(process.env.TEST_VALUE)',
  ]);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '[redacted]');
});

test('代理が持ち主の変数を保存すると、持ち主の別の代理が読み出しコマンドに渡す', async t => {
  const c = await cliFixture(); t.after(c.close);
  const owner = await c.person('Shared owner');
  const unused = await c.person('Unused delegate');
  const writer = JSON.parse((await c.run(['init', '--name', 'Saving delegate', '--origin', c.origin])).stdout);
  const reader = JSON.parse((await c.run(['init', '--name', 'Reading delegate', '--origin', c.origin])).stdout);
  for (const identity of [writer, reader]) await c.context.relations.draw(owner.actor,
    { subjectId: identity.principal.id, relation: 'delegate', objectId: owner.actor.id });
  await c.context.relations.draw(owner.actor, { subjectId: unused.actor.id, relation: 'delegate', objectId: owner.actor.id });
  const kept = await c.run(['keep', 'Shared variable', '--principal', writer.principal.id, '--owner', owner.actor.id, '--stdin'], 'shared-secret-value');
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  const read = await c.run(['read', resource.id, '--principal', reader.principal.id]);
  assert.equal(read.code, 0, read.stderr);
  assert.equal(read.stdout.trim(), 'shared-secret-value');
  const executed = await c.run(['exec', '--principal', reader.principal.id, '--inputs', JSON.stringify([
    { name: 'SHARED_VALUE', source: { id: resource.id } }]), '--', process.execPath, '-e',
    "if(process.env.SHARED_VALUE!=='shared-secret-value')process.exit(1);process.stdout.write('shared variable opened');"]);
  assert.equal(executed.code, 0, executed.stderr);
  assert.equal(executed.stdout, 'shared variable opened');
});

test('発行されたキーでログインした CLI は本人として入り、別の端末が暗号化した変数を読む', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const person = await c.person('Person');
  const headers = { authorization: 'Bearer ' + person.token };
  const issued = await c.app.inject({
    method: 'POST',
    url: `/api/principals/${person.actor.id}/credentials`,
    headers,
    payload: { name: 'Laptop' },
  });
  assert.equal(issued.statusCode, 201, issued.body);
  const { credential, token } = issued.json();
  const refused = await c.run(['login', '--key', token, '--origin', c.origin]);
  assert.notEqual(refused.code, 0);
  assert.match(refused.stderr, /separate encryption unlock code/);
  const unlock = randomBytes(32);
  const wrappedKey = await wrap(person.keys, unlock, person.actor.id);
  const placed = await c.app.inject({
    method: 'PUT',
    url: `/api/principals/${person.actor.id}/credentials/${credential.id}/wrap`,
    headers,
    payload: { wrappedKey, publicKey: publicPart(person.keys.encryption) },
  });
  assert.equal(placed.statusCode, 200, placed.body);
  const keyFile = join(c.directory, 'key.txt');
  await writeFile(keyFile, token + '.' + unlock.toString('base64url') + '\n', { mode: 0o600 });
  const initialized = await c.run(['login', '--key', '@' + keyFile, '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  assert.equal(JSON.parse(initialized.stdout).principal.id, person.actor.id);
  const id = randomUUID();
  await c.context.custody.put(person.actor, { id, name: 'Browser variable', kind: 'variable', ownerId: person.actor.id,
    content: await sealItem(encode('sealed elsewhere'), [person.keys], 1, { bytes: 16 }) });
  const read = await c.run(['read', id]);
  assert.equal(read.code, 0, read.stderr);
  assert.equal(read.stdout, 'sealed elsewhere');
  const status = await c.run(['status']);
  assert.equal(JSON.parse(status.stdout).principal.id, person.actor.id);
});

test('ブラウザで承認すると、ログインを待つ CLI が本人のキーを受け取って入る', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const person = await c.person('Person');
  const headers = { authorization: 'Bearer ' + person.token };
  const waiting = c.start(['login', '--name', 'Laptop', '--origin', c.origin], /enter the code/);
  const shown = await waiting.shown;
  const url = shown.match(/Open (\S+)/)![1]!,
    code = shown.match(/code ([A-Z0-9]{4}-[A-Z0-9]{4})/)![1]!;
  const id = url.split('/').pop()!;
  assert.equal(url, c.origin + '/devices/' + id);
  const device = (await c.app.inject({ url: '/api/auth/devices/' + id, headers })).json();
  assert.equal(device.name, 'Laptop');
  const approved = await c.app.inject({ method: 'POST', url: `/api/auth/devices/${id}/approve`, headers, payload: { code, principalId: person.actor.id } });
  assert.equal(approved.statusCode, 200, approved.body);
  const issued = (await c.app.inject({ method: 'POST', url: `/api/principals/${person.actor.id}/credentials`, headers, payload: { name: 'Laptop' } })).json();
  const unlock = randomBytes(32);
  await c.app.inject({
    method: 'PUT',
    url: `/api/principals/${person.actor.id}/credentials/${issued.credential.id}/wrap`,
    headers,
    payload: { wrappedKey: await wrap(person.keys, unlock, person.actor.id), publicKey: publicPart(person.keys.encryption) },
  });
  const sealed = await seal(encode(issued.token + '.' + unlock.toString('base64url')), [{ id, publicKey: device.publicKey }], 'device:' + id);
  const completed = await c.app.inject({ method: 'POST', url: `/api/auth/devices/${id}/complete`, headers, payload: { sealed } });
  assert.equal(completed.statusCode, 200, completed.body);
  const finished = await waiting.finished;
  assert.equal(finished.code, 0, finished.stderr);
  assert.equal(JSON.parse(finished.stdout).principal.id, person.actor.id);
  const status = await c.run(['status']);
  assert.equal(JSON.parse(status.stdout).principal.id, person.actor.id);
  const saved = JSON.parse(await readFile(join(c.directory, 'foundation', 'identity.json'), 'utf8'));
  assert.equal(saved.current, person.actor.id);
  assert.equal(saved.identities.length, 1);
});

test('UTF8と秘密値の境界をまたぐ出力を最後まで伏せて表示する', () => {
  const secret = '秘密-sensitive/value',
    variants = secretVariants([secret, 'overlap', 'overlapping']);
  for (const value of variants) {
    const source = Buffer.from('before ' + value + ' after');
    for (let split = 1; split < source.length; split++) {
      let output = '';
      const stream = new Redactor(variants, (value) => {
        output += value;
      });
      stream.write(source.subarray(0, split));
      stream.write(source.subarray(split));
      stream.end();
      assert.equal(output, 'before [redacted] after');
    }
  }
});

async function connectionRequester(c: Awaited<ReturnType<typeof cliFixture>>, { delegate = false } = {}) {
  const owner = await c.person('Key owner');
  const initialized = await c.run(['init', '--name', 'Asking machine', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const machine = JSON.parse(initialized.stdout);
  if (delegate)
    await c.context.relations.draw(owner.actor, { subjectId: machine.principal.id, relation: 'delegate', objectId: owner.actor.id });
  const api = { async json<T>(path: string, options: { method?: string; body?: unknown } = {}) {
    const result = await c.app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
      headers: { authorization: 'Bearer ' + owner.token }, ...(options.body !== undefined ? { payload: options.body as object } : {}) });
    assert.ok(result.statusCode < 400, result.body);
    return result.json() as T;
  } };
  const custody = new CustodyClient(api, c.origin, owner.actor.id, owner.keys);
  const flows = new Map();
  const operations = new OperationClient(custody, new ConnectionClient(custody, { async get(id) { return flows.get(id) ?? null; },
    async put(flow) { flows.set(flow.id, flow); } }, { async send() { throw new Error('No service calls are expected.'); } }, 'cli'));
  // The owner saves a connection on its own device, as its browser does.
  const save = async (methodId: string, name: string, material: { fields?: Record<string, string>; aws?: unknown }, connectionId?: string) => {
    const saved = await operations.perform({ name: 'connection.connect', input: { ownerId: owner.actor.id, methodId, name,
      ...(connectionId ? { connectionId } : {}) } }, material as Parameters<typeof operations.perform>[1]);
    if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
    return saved.resource;
  };
  return { owner, machine, api, custody, operations, save };
}

test('持ち主が保存したAPIキーの接続を、委任先のCLIがコマンドへ渡して出力を伏せる', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { save } = await connectionRequester(c, { delegate: true });
  const saved = await save('render:token', 'Render REST', { fields: { token: 'render-connection-secret' } });
  const used = await c.run(['exec', '--inputs', JSON.stringify([
    { name: 'TOKEN', source: { id: saved.id, output: 'RENDER_API_KEY' } },
  ]), '--', process.execPath, '-e', 'process.stdout.write(process.env.TOKEN)']);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '[redacted]');
});

for (const [methodId, output, first, next] of [
  ['fly:token', 'FLY_API_TOKEN', 'FlyV1 fm2_initial_cli_token', 'FlyV1 fm2_updated_cli_token,fm2_discharge'],
  ['resend:api_key', 'RESEND_API_KEY', 're_initial_cli_test_key', 're_updated_cli_test_key'],
  ['cloudrift:api_key', 'CLOUDRIFT_API_KEY', 'cloudrift_initial_cli_test_key', 'cloudrift_updated_cli_test_key'],
] as const)
  test('持ち主が保存し直した' + methodId + 'の値を、CLIが' + output + 'としてコマンドへ渡す', async t => {
    const c = await cliFixture(); t.after(c.close);
    const { save } = await connectionRequester(c, { delegate: true });
    const saved = await save(methodId, 'Service account', { fields: { token: first } });
    assert.equal((await save(methodId, 'Service account', { fields: { token: next } }, saved.id)).id, saved.id);
    const used = await c.run(['exec', '--inputs', JSON.stringify([{ name: output, source: { id: saved.id, output } }]), '--',
      process.execPath, '-e', 'require("node:assert/strict").equal(process.env.' + output + ',' + JSON.stringify(next) +
      ');console.log("credentials delivered");']);
    assert.equal(used.code, 0, used.stderr);
    assert.equal(used.stdout, 'credentials delivered\n');
  });

test('CLIは持ち主に一件の接続を頼み、許可された接続を使い、次から同じ接続を返す', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { owner, api, operations } = await connectionRequester(c);
  const connect = ['connect', 'huggingface', '--owner', owner.actor.id, '--needs', 'HF_TOKEN', '--why', 'List available models'];
  const asked = await c.run(connect);
  assert.equal(asked.code, 0, asked.stderr);
  const request = JSON.parse(asked.stdout);
  assert.deepEqual([request.kind, request.to.id], ['requested', owner.actor.id]);

  const approved = await api.json<{ performed: { id: string } }>('/api/requests/' + request.requestId + '/approve', { method: 'POST', body: {} });
  const token = 'hf_cli_scoped_connection';
  const saved = await operations.continue(approved.performed.id, { fields: { token } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  const waited = await c.run(['connect', 'wait', request.requestId, '--timeout', '5']);
  assert.equal(waited.code, 0, waited.stderr);
  const connected = JSON.parse(waited.stdout);
  assert.deepEqual([connected.kind, connected.connectionId, connected.ownerId, connected.outputs],
    ['connected', saved.resource.id, owner.actor.id, ['HF_TOKEN']]);
  const used = await c.run(['exec', '--inputs', JSON.stringify([
    { name: 'HF_TOKEN', source: { id: connected.connectionId, output: 'HF_TOKEN' } },
  ]), '--', process.execPath, '-e',
    `if (process.env.HF_TOKEN !== ${JSON.stringify(token)}) process.exit(1); console.log('connection ready');`]);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, 'connection ready\n');

  const again = await c.run(connect);
  assert.equal(again.code, 0, again.stderr);
  const existing = JSON.parse(again.stdout);
  assert.deepEqual([existing.kind, existing.connectionId], ['existing', saved.resource.id]);
});

test('鍵の値を渡さないCLIの接続は委任元へ依頼を送り、入力された接続と出力名を返して次からはその接続を返す', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { owner, api, operations } = await connectionRequester(c, { delegate: true });
  const asked = await c.run(['connect', 'cloudrift', '--why', 'Rent a GPU for training']);
  assert.equal(asked.code, 0, asked.stderr);
  const request = JSON.parse(asked.stdout);
  assert.equal(request.kind, 'requested');
  assert.equal(request.to.id, owner.actor.id);
  assert.equal(request.method, 'cloudrift:api_key');
  assert.deepEqual(request.outputs, ['CLOUDRIFT_API_KEY']);
  const received = await api.json<{ message: string; state: string }>('/api/requests/' + request.requestId);
  assert.deepEqual([received.message, received.state], ['Rent a GPU for training', 'pending']);
  const waiting = c.run(['connect', 'wait', request.requestId, '--timeout', '30']);
  const approved = await api.json<{ performed: { id: string } }>('/api/requests/' + request.requestId + '/approve', { method: 'POST', body: {} });
  const saved = await operations.continue(approved.performed.id, { fields: { token: 'cloudrift_requested_key' } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  const waited = await waiting;
  assert.equal(waited.code, 0, waited.stderr);
  const connected = JSON.parse(waited.stdout);
  assert.deepEqual([connected.kind, connected.connectionId, connected.ownerId, connected.outputs],
    ['connected', saved.resource.id, owner.actor.id, ['CLOUDRIFT_API_KEY']]);
  const again = await c.run(['connect', 'CloudRift']);
  assert.equal(again.code, 0, again.stderr);
  assert.deepEqual([JSON.parse(again.stdout).kind, JSON.parse(again.stdout).connectionId], ['existing', saved.resource.id]);
  const another = await c.run(['connect', 'cloudrift', '--new']);
  assert.equal(another.code, 0, another.stderr);
  assert.equal(JSON.parse(another.stdout).kind, 'requested');
});

test('CLIの接続依頼は必要な出力名で接続方法を選び、決まらない方法や依頼先は候補を示して止める', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { owner, machine } = await connectionRequester(c, { delegate: true });
  const ambiguous = await c.run(['connect', 'runpod']);
  assert.equal(ambiguous.code, 1);
  assert.match(ambiguous.stderr, /--needs NAME or --method ID: .*runpod:token \(RUNPOD_API_KEY\)/);
  // An owner this machine does not act for is asked for a key it enters, the method giving the output named.
  const other = await c.person('Other owner');
  const chosen = await c.run(['connect', 'runpod', '--needs', 'RUNPOD_API_KEY', '--owner', other.actor.id]);
  assert.equal(chosen.code, 0, chosen.stderr);
  assert.deepEqual([JSON.parse(chosen.stdout).kind, JSON.parse(chosen.stdout).method], ['requested', 'runpod:token']);
  const second = await c.person('Second owner');
  await c.context.relations.draw(second.actor, { subjectId: machine.principal.id, relation: 'delegate', objectId: second.actor.id });
  const unchosen = await c.run(['connect', 'cloudrift']);
  assert.equal(unchosen.code, 1);
  assert.match(unchosen.stderr, new RegExp('Choose one with --owner: .*' + owner.actor.id));
  const named = await c.run(['connect', 'cloudrift', '--owner', second.actor.id]);
  assert.equal(named.code, 0, named.stderr);
  assert.equal(JSON.parse(named.stdout).to.id, second.actor.id);
});

// The owner keeps a GitHub OAuth application, as its browser saves one.
async function githubApplication(operations: OperationClient, ownerId: string) {
  const saved = await operations.perform({ name: 'app.save', input: { ownerId, name: 'GitHub application', methodId: 'github:oauth',
    clientId: 'github-client-for-machines' } }, { clientSecret: 'github-client-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved application.');
  return saved.resource.id;
}
const authorizeAt = (stdout: string) => {
  const shown = JSON.parse(stdout), url = new URL(shown.authorizationUrl);
  return { kind: shown.kind, id: shown.id, at: url.origin + url.pathname, clientId: url.searchParams.get('client_id') };
};

test('委任先のCLIは、持ち主のアプリでGitHubの認可を自分で始め、持ち主に依頼を送らず、持ち主の項目にできることを表示する', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { owner, api, operations } = await connectionRequester(c, { delegate: true });
  await githubApplication(operations, owner.actor.id);
  const started = await c.run(['connect', 'github', '--method', 'github:oauth', '--why', 'Push packages']);
  assert.equal(started.code, 0, started.stderr);
  const shown = authorizeAt(started.stdout);
  assert.deepEqual([shown.kind, shown.at, shown.clientId],
    ['authorize', 'https://github.com/login/oauth/authorize', 'github-client-for-machines']);
  assert.match(JSON.parse(started.stdout).next, new RegExp('foundation connect continue ' + shown.id));
  const asked = await api.json<{ items: unknown[] }>('/api/requests');
  assert.deepEqual(asked.items, []);
  const status = await c.run(['status']);
  assert.equal(status.code, 0, status.stderr);
  const owned = JSON.parse(status.stdout).principals.find((principal: { id: string }) => principal.id === owner.actor.id);
  assert.deepEqual([owned.permissions, owned.items.connection], [['read', 'use'], ['read', 'update', 'delete', 'reveal']]);
});

test('ブラウザで最後までつなげない接続は、接続を開けてよい機械がその操作の続きを自分で始め、ほかの人を入れる接続は持ち主に残す', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { owner, custody, operations } = await connectionRequester(c, { delegate: true });
  const appId = await githubApplication(operations, owner.actor.id);
  const flows = new Map();
  const browser = new OperationClient(custody, new ConnectionClient(custody, { async get(id) { return flows.get(id) ?? null; },
    async put(flow) { flows.set(flow.id, flow); } }, { async send() { throw new Error('No service calls are expected.'); } }, 'browser'));
  const handed = await browser.perform({ name: 'connection.connect', input: { ownerId: owner.actor.id, methodId: 'github:oauth',
    name: 'GitHub', appId } });
  if (!('kind' in handed) || handed.kind !== 'cli') throw new Error('Expected the browser to hand the connection over.');
  const continued = await c.run(['connect', 'continue', handed.flow.operationId]);
  assert.equal(continued.code, 0, continued.stderr);
  const shown = authorizeAt(continued.stdout);
  assert.deepEqual([shown.kind, shown.at, shown.clientId],
    ['authorize', 'https://github.com/login/oauth/authorize', 'github-client-for-machines']);
  assert.notEqual(shown.id, handed.flow.operationId);
  const other = await c.person('Other user');
  const shared = await browser.perform({ name: 'connection.connect', input: { ownerId: owner.actor.id, methodId: 'github:oauth',
    name: 'Shared GitHub', appId, users: [other.actor.id] } });
  if (!('kind' in shared) || shared.kind !== 'cli') throw new Error('Expected the browser to hand the connection over.');
  const refused = await c.run(['connect', 'continue', shared.flow.operationId]);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /lets others open it, which its owner decides/);
});

test('持ち主が保存したサービスなしのHTTP接続のURLとトークンを、CLIが端末で使う', async t => {
  const c = await cliFixture(); t.after(c.close);
  const { save } = await connectionRequester(c, { delegate: true });
  const connected = { connectionId: (await save('http:bearer', 'My webhook',
    { fields: { url: 'https://receiver.example/private-hook', token: 'cli-private-bearer' } })).id };
  const resource = await c.run(['api', 'GET', '/api/resources/' + connected.connectionId]);
  assert.equal(resource.code, 0, resource.stderr);
  assert.deepEqual(JSON.parse(resource.stdout).data.services, []);
  const used = await c.run(['exec', '--inputs', JSON.stringify([
    { name: 'URL', source: { id: connected.connectionId, output: 'URL' } },
    { name: 'TOKEN', source: { id: connected.connectionId, output: 'TOKEN' } },
  ]), '--', process.execPath, '-e', 'console.log(process.env.URL);console.log(process.env.TOKEN)']);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '[redacted]\n[redacted]\n');
});

test('持ち主が保存したAWS一時認証情報と追加ロールを、CLIがSDKへ渡してAWS APIを呼び出す', async t => {
  const requests: Array<{ action: string; authorization: string; session?: string }> = [];
  const aws = createHttpServer((request, response) => {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      const form = new URLSearchParams(body), action = form.get('Action') ?? '', authorization = String(request.headers.authorization);
      requests.push({ action, authorization, session: request.headers['x-amz-security-token'] as string | undefined });
      response.setHeader('content-type', 'text/xml');
      if (action === 'AssumeRole') response.end('<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">' +
        '<AssumeRoleResult><Credentials><AccessKeyId>assumed-cli-key</AccessKeyId><SecretAccessKey>assumed-cli-secret</SecretAccessKey>' +
        '<SessionToken>assumed-cli-session</SessionToken><Expiration>' + new Date(Date.now() + 3_600_000).toISOString() +
        '</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>');
      else {
        const assumed = authorization.includes('Credential=assumed-cli-key/');
        response.end('<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>' +
          (assumed ? '<Arn>arn:aws:sts::999999999999:assumed-role/Example/cli</Arn><UserId>AROCLI:cli</UserId><Account>999999999999</Account>'
            : '<Arn>arn:aws:iam::123456789012:user/operator</Arn><UserId>AIDOPERATOR</UserId><Account>123456789012</Account>') +
          '</GetCallerIdentityResult></GetCallerIdentityResponse>');
      }
    });
  });
  await new Promise<void>(resolve => aws.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve, reject) => aws.close(error => error ? reject(error) : resolve())));
  const c = await cliFixture({ AWS_REGION: 'us-west-2', AWS_PROFILE: '', AWS_EC2_METADATA_DISABLED: 'true',
    AWS_ACCESS_KEY_ID: 'ambient-cli-key', AWS_SECRET_ACCESS_KEY: 'ambient-cli-secret', AWS_SESSION_TOKEN: 'ambient-cli-session',
    AWS_ENDPOINT_URL_STS: 'http://127.0.0.1:' + (aws.address() as { port: number }).port });
  t.after(c.close);
  const { save } = await connectionRequester(c, { delegate: true });
  const id = (await save('aws:authentication', 'AWS session role', { aws: { authentication: { kind: 'session',
    accessKeyId: 'explicit-cli-key', secretAccessKey: 'explicit-cli-secret', sessionToken: 'explicit-cli-session',
    expiresAt: Date.now() + 3_600_000 }, region: 'us-west-2', role: { arn: 'arn:aws:iam::999999999999:role/team/Example' } } })).id;
  const inputs = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION']
    .map(name => ({ name, source: { id, output: name } }));
  const used = await c.run(['exec', '--inputs', JSON.stringify(inputs), '--', process.execPath, '--input-type=module', '-e',
    'import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";' +
    'const client = new STSClient({endpoint:' +
      JSON.stringify('http://127.0.0.1:' + (aws.address() as { port: number }).port) + '});' +
    'const result = await client.send(new GetCallerIdentityCommand({}));process.stdout.write(result.Account);client.destroy();']);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '999999999999');
  const assumes = requests.filter(request => request.action === 'AssumeRole');
  assert.equal(assumes.length, 1);
  assert.ok(assumes.every(request => request.authorization.includes('Credential=explicit-cli-key/')));
  assert.ok(assumes.every(request => request.session === 'explicit-cli-session'));
  assert.equal(requests.at(-1)!.session, 'assumed-cli-session');
  assert.match(requests.at(-1)!.authorization, /Credential=assumed-cli-key\//);
});

test('CLIのapiで別のプリンシパルに操作を依頼し、承認されたあと行われた操作と履歴を確かめる', async t => {
  const c = await cliFixture(); t.after(c.close);
  const initialized = await c.run(['init', '--name', 'Operation initiator', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const recipient = await c.person('Operation recipient');
  const sent = await c.run(['api', 'POST', '/api/requests', '--body', '@-'], JSON.stringify({ to: recipient.actor.id,
    operation: { name: 'principal.create', input: { ownerId: '$approver', name: 'CLI handoff result' } } }));
  assert.equal(sent.code, 0, sent.stderr);
  const request = JSON.parse(sent.stdout);
  assert.equal(new URL(request.url).pathname, '/requests/' + request.id);
  assert.equal(request.state, 'pending');
  await c.context.requests.approve(recipient.actor, request.id);
  const read = await c.run(['api', 'GET', '/api/requests/' + request.id]);
  assert.equal(read.code, 0, read.stderr);
  const answered = JSON.parse(read.stdout);
  assert.equal(answered.state, 'approved');
  const made = await c.run(['api', 'GET', '/api/operations/' + answered.performed.id]);
  assert.equal(made.code, 0, made.stderr);
  assert.equal(JSON.parse(made.stdout).state, 'succeeded');
  assert.equal(JSON.parse(made.stdout).result.name, 'CLI handoff result');
  const requests = await c.run(['api', 'GET', '/api/requests']);
  assert.equal(requests.code, 0, requests.stderr);
  assert.ok(JSON.parse(requests.stdout).items.some((item: { id: string }) => item.id === request.id));
});
