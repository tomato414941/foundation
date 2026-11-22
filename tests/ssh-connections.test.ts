import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';

async function cliSetup(t: test.TestContext) {
  const reserved = createServer();
  await new Promise<void>(done => reserved.listen(0, '127.0.0.1', done));
  const port = (reserved.address() as { port: number }).port;
  await new Promise<void>(done => reserved.close(() => done()));
  const f = await fixture({ FOUNDATION_ORIGIN: 'http://127.0.0.1:' + port });
  const app = await buildApp(await createContext(f.config, { db: f.db, mailer: f.mailer }));
  const origin = await app.listen({ host: '127.0.0.1', port });
  const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-cli-'));
  t.after(async () => { await app.close(); await f.close(); await rm(directory, { recursive: true, force: true }); });
  const environment: NodeJS.ProcessEnv = { ...process.env, XDG_CONFIG_HOME: directory };
  for (const name of Object.keys(environment)) if (name.startsWith('FOUNDATION_') || name.startsWith('SSH_')) delete environment[name];
  const run = (args: string[], input = '') => new Promise<{ code: number | null; stdout: string; stderr: string }>((done, reject) => {
    const child = spawn(process.execPath, [resolve('cli/dist/cli.mjs'), ...args], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.end(input);
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => done({ code, stdout, stderr }));
  });
  const json = async (args: string[]) => {
    const result = await run(args);
    assert.equal(result.code, 0, result.stderr + result.stdout);
    return JSON.parse(result.stdout);
  };
  assert.equal((await run(['init', '--name', 'Operator', '--origin', origin])).code, 0);
  return { run, json, directory };
}
// A private key file without a passphrase, of the type given, holding the comment given.
async function keyFile(directory: string, type: string, comment = '') {
  const file = join(directory, 'key-' + type);
  await new Promise<void>((done, reject) => spawn('ssh-keygen', ['-q', '-t', type, '-N', '', '-C', comment, '-f', file], { stdio: 'ignore' })
    .once('error', reject).once('close', code => code === 0 ? done() : reject(new Error('ssh-keygen ' + code))));
  return file;
}
type CLI = Awaited<ReturnType<typeof cliSetup>>;
const connect = (c: CLI, name: string, privateKey: string, fields: string[] = []) => c.json(['connect', 'ssh', '--name', name,
  '--field', 'host=server.example.test', '--field', 'user=deploy', '--field', 'privateKey=@' + privateKey, ...fields]);

test('CLIは渡した値でSSHの接続を作り、その鍵をエージェントに入れて接続先とアカウントとともにコマンドへ渡す', async t => {
  const c = await cliSetup(t);
  const made = await connect(c, 'Build server', await keyFile(c.directory, 'ed25519'), ['--field', 'port=2222']);
  assert.equal(made.kind, 'connected');
  const result = await c.run(['ssh-agent', made.connectionId, '--', 'sh', '-c', 'ssh-add -l && echo "$SSH_USER@$SSH_HOST:$SSH_PORT"']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, / Build server \(ED25519\)\ndeploy@server\.example\.test:2222\n$/);
});

// Why: a connection is named by its label in Foundation, which its owner may change; its private key is sealed and is
// not rewritten on a rename. Intent: the agent lists the key by the name the connection has when it is used.
test('SSHの接続の名前を変えると、ssh-add -l に新しい名前が出る', async t => {
  const c = await cliSetup(t);
  const made = await connect(c, 'First name', await keyFile(c.directory, 'ed25519'));
  const connection = await c.json(['api', 'GET', '/api/resources/' + made.connectionId]);
  const renamed = await c.json(['api', 'PATCH', '/api/resources/' + made.connectionId, '--body',
    JSON.stringify({ version: connection.version, name: 'Second name' })]);
  assert.equal(renamed.name, 'Second name');
  const listed = await c.run(['ssh-agent', made.connectionId, '--', 'ssh-add', '-l']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, / Second name \(ED25519\)\n$/);
});

// Why: a key made elsewhere holds the comment it was made with, and the key kept in the connection is not rewritten to
// change it. Intent: such a key, of each type OpenSSH makes, is listed by the connection's name, and kept as it was.
test('名前を中に持つ秘密鍵も、書き換えずに ssh-add -l へ接続の名前で出す', async t => {
  const c = await cliSetup(t);
  for (const type of ['ed25519', 'ecdsa', 'rsa']) {
    const file = await keyFile(c.directory, type, 'name made with');
    const made = await connect(c, 'Current ' + type, file);
    const listed = await c.run(['ssh-agent', made.connectionId, '--', 'ssh-add', '-l']);
    assert.equal(listed.code, 0, listed.stderr);
    assert.match(listed.stdout, new RegExp(' Current ' + type + ' \\([A-Z0-9-]+\\)\n$'), type);
    const copy = join(c.directory, 'copy-' + type);
    const kept = await c.run(['exec', '--inputs', JSON.stringify([{ name: 'KEY', source: { id: made.connectionId, output: 'SSH_PRIVATE_KEY' } }]),
      '--', 'sh', '-c', 'cp "$KEY" "$1"', 'sh', copy]);
    assert.equal(kept.code, 0, kept.stderr);
    assert.equal(await readFile(copy, 'utf8'), await readFile(file, 'utf8'), type);
  }
});

test('CLIは秘密鍵を読み込めないとき、待ち続けずに後片付けしてエラーで終わる', async t => {
  const c = await cliSetup(t);
  const broken = join(c.directory, 'broken');
  await writeFile(broken, '-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----\n');
  const made = await connect(c, 'Broken', broken);
  const started = Date.now();
  const result = await c.run(['ssh-agent', made.connectionId, '--', 'true']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /could not be loaded into an SSH agent/);
  assert.ok(Date.now() - started < 30_000);
});

test('ssh-agent は、SSHの秘密鍵を持たない接続ではコマンドを動かさない', async t => {
  const c = await cliSetup(t);
  const made = await c.json(['connect', 'cloudrift', '--field', 'token=not-a-real-token']);
  const result = await c.run(['ssh-agent', made.connectionId, '--', 'node', '-e', 'process.stdout.write("ran")']);
  assert.equal(result.code, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Choose an SSH connection/);
});

test('SSHの接続先とアカウントには、コマンドのオプションと読める値を受け付けない', async t => {
  const c = await cliSetup(t);
  const key = await keyFile(c.directory, 'ed25519');
  for (const [host, user] of [['-oProxyCommand=true', 'deploy'], ['server.example.test', '-oProxyCommand=true']]) {
    const result = await c.run(['connect', 'ssh', '--field', 'host=' + host, '--field', 'user=' + user, '--field', 'privateKey=@' + key]);
    assert.equal(result.code, 1, host + ' ' + user);
  }
  const listed = await c.json(['api', 'GET', '/api/principals/' + (await c.json(['status'])).principal.id + '/resources?kind=connection']);
  assert.deepEqual(listed.items, []);
});
