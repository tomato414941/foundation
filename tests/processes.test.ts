import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile, mkdir } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { publicPart } from '../shared/authority.js';
import { CreatedProcess, ProcessView } from '../shared/process.js';
import { CommandProcess } from '../runtime/command.js';
import { ProcessBroker, ProcessExecutor } from '../runtime/process.js';
import { HttpBroker } from '../runtime/broker.js';

async function processFixture(t: TestContext) {
  const f = await flowFixture();
  t.after(f.close);
  const environmentId = f.environment.manifest.id;
  const directory = join(f.config.dataDirectory, 'workspace');
  await mkdir(directory);
  const executorApi = (f.executor.broker as HttpBroker).api;
  await executorApi.json('/api/environments/' + environmentId + '/processes/registration', {
    method: 'PUT', body: { workingDirectory: directory },
  });
  const enrolled = await f.authentication.enroll('API principal', publicPart(f.owner.keys.encryption));
  const caller = { token: enrolled.token, actor: (await f.authentication.authenticate(enrolled.token))! };
  await f.relations.draw(f.owner.actor, { subjectId: caller.actor.id, relation: 'runner', objectId: environmentId });
  await f.relations.draw(f.owner.actor, { subjectId: caller.actor.id, relation: 'reader', objectId: environmentId });
  const api = f.api(caller.token), journal = new MemoryJournal(), broker = new ProcessBroker(executorApi);
  const worker = new ProcessExecutor(environmentId, broker, journal, new CommandProcess({ isolation: 'process' }), 20);
  const create = (body: object) => api.json('/api/environments/' + environmentId + '/processes', { method: 'POST', body }, CreatedProcess);
  const get = (id: string) => api.json('/api/processes/' + id, {}, ProcessView);
  return { ...f, environmentId, directory, caller, callerApi: api, journal, broker, worker, create, get };
}

test('APIキーでコマンド、作業ディレクトリ、環境変数と標準入力を渡して終了結果を取得する', async t => {
  const f = await processFixture(t);
  const subdirectory = join(f.directory, 'project'); await mkdir(subdirectory);
  const program = 'let input="";process.stdin.on("data",chunk=>input+=chunk);process.stdin.on("end",()=>{' +
    'process.stdout.write(JSON.stringify({cwd:process.cwd(),value:process.env.VALUE,input}));process.stderr.write("diagnostic")})';
  const started = await f.create({ command: ['node', '-e', program], workingDirectory: subdirectory,
    environment: { VALUE: 'specified value' }, stdin: 'provided input', timeoutSeconds: 5 });
  assert.equal(started.state, 'queued');
  assert.equal(started.actorId, f.caller.actor.id);
  await f.worker.tick();
  const finished = await f.get(started.id);
  assert.equal(finished.state, 'succeeded');
  assert.equal(finished.result!.exitCode, 0);
  assert.equal(finished.result!.signal, null);
  assert.equal(finished.result!.stderr, 'diagnostic');
  assert.deepEqual(JSON.parse(finished.result!.stdout), { cwd: subdirectory, value: 'specified value', input: 'provided input' });
});

test('同じ実行IDで再送したコマンドを一度実行し、環境のファイルを次のコマンドで読む', async t => {
  const f = await processFixture(t);
  const body = { id: crypto.randomUUID(), command: ['node', '-e', 'require("fs").appendFileSync("count","1")'] };
  const first = await f.create(body), again = await f.create(body);
  assert.equal(first.id, again.id);
  await f.worker.tick();
  assert.equal((await f.create(body)).state, 'succeeded');
  const reader = await f.create({ command: ['node', '-e', 'process.stdout.write(require("fs").readFileSync("count"))'] });
  await f.worker.tick();
  assert.equal((await f.get(reader.id)).result!.stdout, '1');
  await assert.rejects(f.create({ ...body, command: ['node', '-e', 'process.exit(0)'] }), /new process ID/);
});

test('コマンドの終了コード、終了シグナル、制限時間と出力上限を結果へ反映する', async t => {
  const f = await processFixture(t);
  const failure = await f.create({ command: ['node', '-e', 'process.stderr.write("failed command");process.exit(7)'] });
  await f.worker.tick();
  const failed = await f.get(failure.id);
  assert.equal(failed.state, 'failed'); assert.equal(failed.result!.exitCode, 7);
  assert.equal(failed.result!.stderr, 'failed command');
  const signalled = await f.create({ command: ['node', '-e', 'process.kill(process.pid,"SIGTERM")'] });
  await f.worker.tick();
  assert.equal((await f.get(signalled.id)).result!.signal, 'SIGTERM');
  const timed = await f.create({ command: ['node', '-e', 'setInterval(()=>{},1000)'], timeoutSeconds: 1 });
  await f.worker.tick();
  assert.equal((await f.get(timed.id)).result!.timedOut, true);
  const large = await f.create({ command: ['node', '-e', 'process.stdout.write("x".repeat(1_000_005))'] });
  await f.worker.tick();
  const result = (await f.get(large.id)).result!;
  assert.equal(result.truncated, true); assert.equal(result.stdout.length, 1_000_000);
});

test('許可されたプリンシパルが実行し、権限を解除した要求を開始前に拒否する', async t => {
  const f = await processFixture(t);
  await assert.rejects(f.api(f.stranger.token).json('/api/environments/' + f.environmentId + '/processes', {
    method: 'POST', body: { command: ['node', '-e', 'process.exit(0)'] },
  }), /permission/);
  const started = await f.create({ command: ['node', '-e', 'process.stdout.write("allowed")'] });
  await f.relations.erase(f.owner.actor, { subjectId: f.caller.actor.id, relation: 'runner', objectId: f.environmentId });
  await f.worker.tick();
  const failed = await f.get(started.id);
  assert.equal(failed.state, 'failed'); assert.equal(failed.error, 'authorization_changed');
});

test('実行出力をUnicode文字ごとに区切り、続きの位置から取得する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'process.stdout.write("a😀あb");process.stderr.write("error")'] });
  await f.worker.tick();
  const first = await f.callerApi.json<{ text: string; next: number }>('/api/processes/' + started.id + '/output?limit=2');
  assert.equal(first.text, 'a😀'); assert.equal(first.next, 2);
  const second = await f.callerApi.json<{ text: string; next: number | null }>('/api/processes/' + started.id + '/output?offset=2');
  assert.equal(second.text, 'あb'); assert.equal(second.next, null);
  const stderr = await f.callerApi.json<{ text: string }>('/api/processes/' + started.id + '/output?stream=stderr');
  assert.equal(stderr.text, 'error');
});

test('実行中に利用権限を解除したコマンドを停止して終了を確認する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'setInterval(()=>{},1000)'] });
  const running = f.worker.tick();
  for (let index = 0; index < 100; index++) {
    if ((await f.get(started.id)).startedAt) break;
    await delay(10);
  }
  await f.relations.erase(f.owner.actor, { subjectId: f.caller.actor.id, relation: 'runner', objectId: f.environmentId });
  await running;
  assert.equal((await f.get(started.id)).state, 'cancelled');
});

test('実行を取得した後も権限を確認し、解除されたコマンドの開始を拒否する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'process.stdout.write("allowed")'] });
  const claim = await f.broker.claim(f.environmentId);
  assert.equal(claim!.process.id, started.id);
  await f.relations.erase(f.owner.actor, { subjectId: f.caller.actor.id, relation: 'runner', objectId: f.environmentId });
  await assert.rejects(f.broker.dispatch(started.id, claim!.lease), /permission/);
});

test('待機中のコマンドを中止し、実行中のコマンドを停止して結果を確定する', async t => {
  const f = await processFixture(t);
  const queued = await f.create({ command: ['node', '-e', 'process.exit(0)'] });
  const cancelled = await f.callerApi.json('/api/processes/' + queued.id + '/cancel', { method: 'POST', body: {} }, ProcessView);
  assert.equal(cancelled.state, 'cancelled');
  const started = await f.create({ command: ['node', '-e', 'setInterval(()=>{},1000)'] });
  const running = f.worker.tick();
  for (let index = 0; index < 100; index++) {
    if ((await f.get(started.id)).startedAt) break;
    await delay(10);
  }
  await f.callerApi.json('/api/processes/' + started.id + '/cancel', { method: 'POST', body: {} });
  await running;
  assert.equal((await f.get(started.id)).state, 'cancelled');
});

test('実行結果の送信が途切れた場合に記録から結果を届け、コマンドを一度で完了する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'require("fs").appendFileSync("completed","1")'] });
  const finish = f.broker.finish.bind(f.broker);
  f.broker.finish = async () => { throw new Error('Connection lost'); };
  await assert.rejects(f.worker.tick(), /delivery/);
  await f.db.pool.query("UPDATE environment_processes SET lease_until=now()-interval '1 second' WHERE id=$1", [started.id]);
  await f.context.processes.recover();
  assert.equal((await f.get(started.id)).state, 'uncertain');
  f.broker.finish = finish;
  const restarted = new ProcessExecutor(f.environmentId, f.broker, f.journal, new CommandProcess({ isolation: 'process' }));
  assert.deepEqual(await restarted.reconcile(), []);
  assert.equal((await f.get(started.id)).state, 'succeeded');
  assert.equal(await readFile(join(f.directory, 'completed'), 'utf8'), '1');
});

test('環境を停止して待機中のコマンドを中止し、新しい実行要求を拒否する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'process.exit(0)'] });
  await f.delegation.stop(f.owner.actor, f.environmentId);
  assert.equal((await f.get(started.id)).state, 'cancelled');
  await assert.rejects(f.create({ command: ['node', '-e', 'process.exit(0)'] }), /running execution environment/);
});

test('環境の停止前に取得済みのコマンドを中止として確定する', async t => {
  const f = await processFixture(t);
  const started = await f.create({ command: ['node', '-e', 'process.exit(0)'] });
  const claim = await f.broker.claim(f.environmentId);
  await f.delegation.stop(f.owner.actor, f.environmentId);
  const finished = await f.broker.finish(started.id, claim!.lease, { state: 'failed', result: null, error: 'process_failed' });
  assert.equal(finished.state, 'cancelled');
  assert.equal((await f.get(started.id)).state, 'cancelled');
});

test('HTTPのMCPから共通APIでコマンドを実行し、実行IDで結果を取得する', async t => {
  const f = await processFixture(t);
  const origin = await f.app.listen({ host: '127.0.0.1', port: 0 });
  const client = new McpClient({ name: 'api-process-test', version: '1' });
  await client.connect(new StreamableHTTPClientTransport(new URL('/api/mcp', origin), {
    requestInit: { headers: { authorization: 'Bearer ' + f.caller.token } },
  }));
  t.after(() => client.close());
  const submitted = await client.callTool({ name: 'foundation_api', arguments: {
    method: 'POST', path: '/api/environments/' + f.environmentId + '/processes',
    body: { command: ['node', '-e', 'process.stdout.write("MCP through API")'], stdin: 'x'.repeat(30000) },
  } });
  assert.notEqual(submitted.isError, true, JSON.stringify(submitted));
  const data = submitted.structuredContent!.data as { status: number; body: { id: string } };
  assert.equal(data.status, 202);
  await f.worker.tick();
  const inspected = await client.callTool({ name: 'foundation_api', arguments: { method: 'GET', path: '/api/processes/' + data.body.id + '/output' } });
  assert.notEqual(inspected.isError, true, JSON.stringify(inspected));
  const result = inspected.structuredContent!.data as { body: { state: string; text: string; exitCode: number } };
  assert.equal(result.body.state, 'succeeded'); assert.equal(result.body.exitCode, 0);
  assert.equal(result.body.text, 'MCP through API');
});
