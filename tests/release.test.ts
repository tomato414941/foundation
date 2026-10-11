import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { flowFixture } from './flow-support.js';
import { Task } from '../shared/runtime-protocol.js';
import { CreatedProcess, ProcessView } from '../shared/process.js';
import { HttpBroker } from '../runtime/broker.js';
import { ProcessBroker, ProcessExecutor } from '../runtime/process.js';
import { CommandProcess } from '../runtime/command.js';
import { MemoryJournal } from './delegation-support.js';
import { checkPublishedContent } from '../.github/scripts/cli-release.mjs';

test('公開済みCLIと同じ内容を許可し、配布内容の変更にはバージョン変更を要求する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-package-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(join(directory, 'package/dist'), { recursive: true });
  await writeFile(join(directory, 'package/dist/cli.mjs'), 'original-cli');
  const packed = execFileSync('tar', ['-czf', '-', '-C', directory, 'package']);
  const pkg = { version: '5.1.0' };
  const registry = { versions: { '5.1.0': { dist: { tarball: 'https://registry.npmjs.org/package.tgz',
    integrity: 'sha512-' + createHash('sha512').update(packed).digest('base64') } } } };
  const fetcher = async () => new Response(packed);
  await checkPublishedContent(pkg, registry, Buffer.from('original-cli'), fetcher);
  await assert.rejects(checkPublishedContent(pkg, registry, Buffer.from('updated-cli'), fetcher), /Increase/);
});

test('更新待機中は新規処理を受け取らず、再開後に待っていた処理を実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const environment = f.environment.manifest.id, executor = { id: f.executor.binding.principalId };
  const task = await f.client.submit(f.owner.actor.id, environment,
    { kind: 'command', command: ['node', '-e', 'console.log("ready")'], inputs: [], timeoutSeconds: 5 });
  assert.equal((await f.context.delegation.maintenance(executor, environment, true)).paused, true);
  assert.equal(await f.executor.tick(), false);
  assert.equal((await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)).state, 'queued');
  await f.context.delegation.maintenance(executor, environment, false);
  assert.equal(await f.executor.tick(), true);
  assert.equal((await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)).state, 'succeeded');
});

test('更新要求の期限が切れたら実行環境が処理を再開する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const environment = f.environment.manifest.id, executor = { id: f.executor.binding.principalId };
  await f.context.delegation.maintenance(executor, environment, true);
  await f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{maintenanceUntil}',to_jsonb($2::text)) WHERE id=$1",
    [environment, new Date(Date.now() - 1000).toISOString()]);
  assert.equal((await f.context.delegation.maintenance(executor, environment)).paused, false);
  const task = await f.client.submit(f.owner.actor.id, environment,
    { kind: 'command', command: ['node', '-e', 'console.log("ready")'], inputs: [], timeoutSeconds: 5 });
  assert.equal(await f.executor.tick(), true);
  assert.equal((await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)).state, 'succeeded');
});

test('実行環境の運営者だけが更新待機を操作する', async t => {
  const f = await flowFixture(); t.after(f.close);
  await assert.rejects(f.context.delegation.maintenance(f.stranger.actor, f.environment.manifest.id, true));
});

test('更新待機中は通常のコマンドも待機させ、再開後に実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const environment = f.environment.manifest.id, executor = { id: f.executor.binding.principalId };
  const executorApi = (f.executor.broker as HttpBroker).api;
  await executorApi.json('/api/environments/' + environment + '/processes/registration', {
    method: 'PUT', body: { workingDirectory: f.config.dataDirectory },
  });
  const api = f.api(f.owner.token);
  const process = await api.json('/api/environments/' + environment + '/processes', {
    method: 'POST', body: { command: ['node', '-e', 'console.log("ready")'] },
  }, CreatedProcess);
  const worker = new ProcessExecutor(environment, new ProcessBroker(executorApi), new MemoryJournal(),
    new CommandProcess({ isolation: 'process' }));
  await f.context.delegation.maintenance(executor, environment, true);
  assert.equal(await worker.tick(), false);
  assert.equal((await api.json('/api/processes/' + process.id, {}, ProcessView)).state, 'queued');
  await f.context.delegation.maintenance(executor, environment, false);
  assert.equal(await worker.tick(), true);
  assert.equal((await api.json('/api/processes/' + process.id, {}, ProcessView)).state, 'succeeded');
});
