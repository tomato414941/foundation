import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Redactor, secretVariants } from '../cli/src/execute.js';
import { encode, seal, wrap } from '../shared/encryption.js';
import { AccessPolicy, protect } from '../shared/custody.js';
import { bindKeys, hash, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';
import { LegacySecrets } from '../server/legacy-secrets.js';

async function cliFixture() {
  const reserved = createServer();
  await new Promise<void>(resolve => reserved.listen(0, '127.0.0.1', resolve));
  const port = (reserved.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => reserved.close(error => error ? reject(error) : resolve()));
  const f = await fixture({ FOUNDATION_ORIGIN: 'http://127.0.0.1:' + port }),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  const origin = await app.listen({ host: '127.0.0.1', port }),
    directory = await mkdtemp(join(tmpdir(), 'foundation-cli-test-'));
  const environment = { ...process.env, XDG_CONFIG_HOME: directory };
  for (const key of [
    'FOUNDATION_ORIGIN',
    'FOUNDATION_TOKEN',
    'FOUNDATION_PRINCIPAL_ID',
    'FOUNDATION_PRIVATE_KEY',
    'FOUNDATION_PRIVATE_KEYS',
    'FOUNDATION_KEY_BINDING',
  ])
    delete environment[key];
  async function run(args: string[], input?: string) {
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveResult, reject) => {
      const child = spawn(process.execPath, [resolve('cli/dist/cli.mjs'), ...args], {
        env: environment,
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
  function start(args: string[], until: RegExp) {
    const child = spawn(process.execPath, [resolve('cli/dist/cli.mjs'), ...args], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    const finished = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveResult) =>
      child.once('close', (code) => resolveResult({ code, stdout, stderr })));
    const shown = new Promise<string>((resolveShown) =>
      child.stderr.on('data', (chunk) => { stderr += chunk; if (until.test(stderr)) resolveShown(stderr); }));
    child.stdin.end();
    return { shown, finished };
  }
  async function close() {
    await app.close();
    await f.close();
    await rm(directory, { recursive: true, force: true });
  }
  async function person(name: string) {
    const keys = await newIdentityKeys();
    const enrolled = await f.authentication.enroll(name, publicPart(keys.encryption));
    const actor = (await f.authentication.authenticate(enrolled.token))!;
    const binding = bindKeys(actor.id, keys);
    await context.bindings.publish(actor, await signBinding(binding, keys));
    return { ...enrolled, actor, keys, binding };
  }
  return { f, context, app, origin, directory, run, start, close, person };
}

test('移行済みの秘密を使用権限でローカルコマンドへ渡し、内容の読み出しを制限する', async t => {
  const c = await cliFixture(); t.after(c.close);
  const initialized = await c.run(['init', '--name', 'Legacy executor', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const identity = JSON.parse(await readFile(join(c.directory, 'foundation', 'identity.json'), 'utf8')).identities[0];
  const owner = await c.person('Legacy owner'), id = crypto.randomUUID();
  await c.context.principals.relate(owner.actor, identity.principalId, 'agent', owner.actor.id);
  const bytes = encode('legacy-cli-token');
  await c.context.resources.insert(owner.actor.id, 'secret', 'Legacy CLI secret',
    { allowUse: true, bytes: bytes.length }, { id,
      sealed: await seal(bytes, [{ id: owner.actor.id, publicKey: publicPart(owner.keys.encryption) }], 'resource:' + id) });
  const legacy = new LegacySecrets(c.context.custody), plan = await legacy.plan(owner.actor, id);
  await legacy.complete(owner.actor, { name: plan.name, version: plan.version,
    content: await protect(bytes, plan.policy, 1, owner.binding, owner.keys) });
  const trusted = await c.run(['trust', owner.actor.id, '--fingerprint', await hash(owner.binding)]);
  assert.equal(trusted.code, 0, trusted.stderr);
  const executed = await c.run(['exec', '--inputs', JSON.stringify([
    { name: 'LEGACY_VALUE', source: { kind: 'secret', id } },
  ]), '--', process.execPath, '-e', 'if(process.env.LEGACY_VALUE!=="legacy-cli-token")process.exit(2);console.log("Secret used");']);
  assert.equal(executed.code, 0, executed.stderr);
  assert.match(executed.stdout, /Secret used/);
  const read = await c.run(['read', id]);
  assert.equal(read.code, 1);
  assert.match(read.stderr, /cannot reveal/);
});

test('CLIで登録してシークレットを保存し、コマンドへ渡して出力を伏せる', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const initialized = await c.run(['init', '--name', 'CLI test', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const identityPath = join(c.directory, 'foundation', 'identity.json');
  assert.equal((await stat(identityPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(c.directory, 'foundation'))).mode & 0o777, 0o700);
  const kept = await c.run(['keep', 'CLI secret', '--stdin'], '秘密-value/123');
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  assert.equal(resource.kind, 'secret');
  assert.equal(resource.data.custodyRevision, 1);
  const output = join(c.directory, 'revealed.txt'),
    read = await c.run(['read', resource.id, '--output', output]);
  assert.equal(read.code, 0, read.stderr);
  assert.equal(await readFile(output, 'utf8'), '秘密-value/123');
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  const fileRecord = join(c.directory, 'file-path');
  const inputs = JSON.stringify([
    { name: 'TEST_VALUE', source: { kind: 'secret', id: resource.id } },
    { name: 'TEST_FILE', source: { kind: 'secret', id: resource.id }, format: 'file' },
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
  const exported = join(c.directory, 'export.ndjson'),
    exportResult = await c.run(['export', '--output', exported]);
  assert.equal(exportResult.code, 0, exportResult.stderr);
  assert.equal((await stat(exported)).mode & 0o777, 0o600);
  assert.ok((await readFile(exported, 'utf8')).includes('CLI secret'));
  const exportedResource = (await readFile(exported, 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    .find(item => item.type === 'resource');
  assert.equal(exportedResource.custody.policy.id, resource.id);
});

test('CLIの確認コードを承認し、同じAPIから所有者のリソースを利用する', async (t) => {
  const c = await cliFixture();
  t.after(c.close);
  const owner = await c.person('Human owner');
  const initialized = await c.run(['init', '--name', 'Joining machine', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const joined = await c.run(['join']);
  assert.equal(joined.code, 0, joined.stderr);
  const request = JSON.parse(joined.stdout);
  assert.match(request.code, /^[A-Z0-9]{8}$/);
  assert.equal(request.canRespond, false);
  const approved = await c.app.inject({
    method: 'POST',
    url: '/api/requests/' + request.id + '/approve',
    headers: { authorization: 'Bearer ' + owner.token },
    payload: { code: request.code },
  });
  assert.equal(approved.statusCode, 200, approved.body);
  const waited = await c.run(['request', 'wait', request.id, '--timeout', '5']);
  assert.equal(waited.code, 0, waited.stderr);
  assert.equal(JSON.parse(waited.stdout).state, 'approved');
  const status = await c.run(['status']);
  assert.equal(status.code, 0, status.stderr);
  assert.ok(JSON.parse(status.stdout).principals.some((item: { id: string }) => item.id === owner.actor.id));
  const trusted = await c.run(['trust', owner.actor.id, '--fingerprint', await hash(owner.binding)]);
  assert.equal(trusted.code, 0, trusted.stderr);
  const kept = await c.run(
    ['keep', 'Owner secret', '--owner', owner.actor.id, '--stdin'],
    'delegated-value',
  );
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  const used = await c.run([
    'exec',
    '--inputs',
    JSON.stringify([{ name: 'TEST_VALUE', source: { kind: 'secret', id: resource.id } }]),
    '--',
    process.execPath,
    '-e',
    'process.stdout.write(process.env.TEST_VALUE)',
  ]);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '[redacted]');
});

test('発行されたキーでログインした CLI は本人として入り、別の端末が封じたシークレットを読む', async (t) => {
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
  const id = randomUUID(),
    content = encode('sealed elsewhere');
  const policy = AccessPolicy.parse({ format: 1, id, origin: c.origin, ownerId: person.actor.id, kind: 'secret',
    revision: 1, authorities: [person.binding], readers: [person.binding], grants: [] });
  await c.context.custody.put(person.actor, {
    name: 'Browser secret',
    content: await protect(content, policy, 1, person.binding, person.keys),
  });
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

test('CLIで実行先を登録し、指定した実行先へ暗号化したコマンドを送り結果を復号する', async t => {
  const c = await cliFixture(); t.after(c.close);
  const initialized = await c.run(['init', '--name', 'Executor', '--origin', c.origin]);
  assert.equal(initialized.code, 0, initialized.stderr);
  const id = randomUUID();
  const registered = await c.run(['agent', 'start', '--id', id, '--once']);
  assert.equal(registered.code, 0, registered.stderr);
  assert.equal(JSON.parse(registered.stdout).environmentId, id);
  const kept = await c.run(['keep', 'Command credential', '--stdin', '--for', id], 'command-secret');
  assert.equal(kept.code, 0, kept.stderr);
  const resource = JSON.parse(kept.stdout);
  const run = await c.run(['run', '--environment', id, '--inputs', JSON.stringify([
    { name: 'TOKEN', source: { kind: 'secret', id: resource.id } },
  ]), '--', process.execPath, '-e', 'process.stdout.write("executed:" + process.env.TOKEN)']);
  assert.equal(run.code, 0, run.stderr);
  const executed = await c.run(['agent', 'start', '--id', id, '--once']);
  assert.equal(executed.code, 0, executed.stderr);
  const result = await c.run(['wait', JSON.parse(run.stdout).id, '--timeout', '5']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).result.stdout, 'executed:[redacted]');
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

test('CLIで接続を実行先へ依頼し、確認した接続を暗号化して保存してから端末で利用する', async t => {
  const c = await cliFixture(); t.after(c.close);
  assert.equal((await c.run(['init', '--name', 'Connection owner', '--origin', c.origin])).code, 0);
  const environment = randomUUID();
  const registered = await c.run(['agent', 'start', '--id', environment, '--once']);
  assert.equal(registered.code, 0, registered.stderr);
  const start = await c.run(['connect', '--method', 'render:token', '--environment', environment,
    '--name', 'Render REST', '--fields', '@-'], '{"token":"render-connection-secret"}');
  assert.equal(start.code, 0, start.stderr);
  const flow = JSON.parse(start.stdout).flowId;
  const execute = await c.run(['agent', 'start', '--id', environment, '--once']);
  assert.equal(execute.code, 0, execute.stderr);
  const review = await c.run(['connect', 'status', flow]);
  assert.equal(review.code, 0, review.stderr);
  assert.equal(JSON.parse(review.stdout).kind, 'review');
  assert.equal(JSON.parse(review.stdout).metadata.methodId, 'render:token');
  const accept = await c.run(['connect', 'accept', flow]);
  assert.equal(accept.code, 0, accept.stderr);
  const saved = await c.run(['agent', 'start', '--id', environment, '--once']);
  assert.equal(saved.code, 0, saved.stderr);
  const connected = await c.run(['connect', 'status', flow]);
  assert.equal(connected.code, 0, connected.stderr);
  assert.equal(JSON.parse(connected.stdout).kind, 'connected');
  const id = JSON.parse(connected.stdout).id;
  const used = await c.run(['exec', '--inputs', JSON.stringify([
    { name: 'TOKEN', source: { kind: 'connection', id, output: 'RENDER_API_KEY' } },
  ]), '--', process.execPath, '-e', 'process.stdout.write(process.env.TOKEN)']);
  assert.equal(used.code, 0, used.stderr);
  assert.equal(used.stdout, '[redacted]');
});
