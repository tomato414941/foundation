import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { Executor } from '../runtime/executor.js';
import { FileJournal } from '../runtime/journal.js';
import { CommandProcess, childEnvironment } from '../runtime/command.js';
import { hash } from '../shared/authority.js';
import { approvePolicy, prepareRun, reveal } from '../shared/custody.js';
import { readReceipt } from '../shared/execution.js';
import { decode, encode } from '../shared/encryption.js';
import type { OutboundRequest, Transport } from '../server/transport.js';
import type { JsonValue } from '../shared/contracts.js';

test('実行先で秘密を復号してHTTP要求へ渡し、依頼者が暗号化された結果を復号する', async () => {
  const f = await delegatedFixture();
  try {
    const requests: OutboundRequest[] = [];
    const transport: Transport = { async send(input) {
      requests.push(input);
      return { status: 200, headers: {}, body: encode('received confidential-value') };
    } };
    const operation = { kind: 'http', request: { url: 'https://service.example/items', method: 'POST',
      headers: {}, body: 'request-body', bindings: [{ pointer: '/headers/authorization',
        parts: ['Bearer ', { kind: 'secret', id: f.policy.id }] }] } };
    const intent = { ...f.intent, operationDigest: await hash(operation) };
    await f.delegation.submit(f.owner.actor, await prepareRun(intent, operation, f.owner.keys));
    const executor = new Executor(f.environment, f.executor.keys, f.broker, new MemoryJournal(), transport,
      new CommandProcess({ isolation: 'process' }));
    assert.equal(await executor.tick(), true);
    const task = await f.delegation.get(f.owner.actor, intent.id);
    assert.equal(task.state, 'succeeded');
    assert.equal(requests.length, 1);
    assert.equal(requests[0]!.headers!.authorization, 'Bearer confidential-value');
    const result = await readReceipt(task.receipt!, intent, f.owner.binding.id, f.owner.keys);
    assert.deepEqual(result.result, { status: 200, headers: {}, body: 'received [redacted]' });
  } finally { await f.close(); }
});

test('実行結果を送れない場合は記録から再送し、外部操作を一度で完了する', async () => {
  const f = await delegatedFixture();
  try {
    let calls = 0;
    const transport: Transport = { async send() { calls++; return { status: 200, headers: {}, body: encode('ok') }; } };
    const journal = new MemoryJournal();
    const commands = new CommandProcess({ isolation: 'process' });
    await f.delegation.submit(f.owner.actor, f.request);
    const first = new Executor(f.environment, f.executor.keys, { ...f.broker,
      async finish() { throw new Error('offline'); } }, journal, transport, commands);
    await assert.rejects(first.tick(), /offline/);
    const restarted = new Executor(f.environment, f.executor.keys, f.broker, journal, transport, commands);
    await restarted.reconcile();
    await restarted.reconcile();
    assert.equal(calls, 1);
    assert.equal((await f.delegation.get(f.owner.actor, f.intent.id)).state, 'succeeded');
  } finally { await f.close(); }
});

test('応答を受け取れない外部操作を確認待ちとして保持し、再起動後もその記録を利用する', async () => {
  const f = await delegatedFixture();
  try {
    let calls = 0;
    const transport: Transport = { async send() { calls++; throw new Error('response lost'); } };
    const journal = new MemoryJournal();
    const commands = new CommandProcess({ isolation: 'process' });
    await f.delegation.submit(f.owner.actor, f.request);
    const executor = new Executor(f.environment, f.executor.keys, f.broker, journal, transport, commands);
    await executor.tick();
    assert.equal((await f.delegation.get(f.owner.actor, f.intent.id)).state, 'uncertain');
    await new Executor(f.environment, f.executor.keys, f.broker, journal, transport, commands).reconcile();
    assert.equal(await executor.tick(), false);
    assert.equal(calls, 1);
  } finally { await f.close(); }
});

test('実行先の記録を署名付きで暗号化し、同じ実行先の鍵で再起動後に復元する', async () => {
  const f = await delegatedFixture();
  try {
    const directory = join(f.config.dataDirectory, 'journal');
    const journal = new FileJournal(directory, f.config.origin, f.executor.binding, f.executor.keys);
    const key = 'run_' + crypto.randomUUID(), value = { token: 'journal-secret', revision: 2 };
    await journal.write(key, value);
    const reopened = new FileJournal(directory, f.config.origin, f.executor.binding, f.executor.keys);
    assert.deepEqual(await reopened.read(key), value);
    assert.deepEqual(await reopened.keys('run_'), [key]);
    assert.equal((await lstat(join(directory, key + '.json'))).mode & 0o777, 0o600);
    await assert.rejects(new FileJournal(directory, f.config.origin, f.stranger.binding, f.stranger.keys).read(key));
    await assert.rejects(journal.write('run_../../escape', value));
  } finally { await f.close(); }
});

test('コマンドへ指定した入力だけを渡し、終了結果とマスクした出力を返す', async () => {
  const f = await delegatedFixture();
  try {
    const operation = { kind: 'command', command: ['node', '-e', 'process.stdout.write(process.env.TOKEN)'],
      timeoutSeconds: 5, inputs: [{ name: 'TOKEN', source: { kind: 'secret', id: f.policy.id }, format: 'text' }] };
    const intent = { ...f.intent, operation: 'command' as const, operationDigest: await hash(operation) };
    await f.delegation.submit(f.owner.actor, await prepareRun(intent, operation, f.owner.keys));
    const executor = new Executor(f.environment, f.executor.keys, f.broker, new MemoryJournal(),
      { async send() { throw new Error('Unexpected HTTP request'); } }, new CommandProcess({ isolation: 'process' }));
    await executor.tick();
    const task = await f.delegation.get(f.owner.actor, intent.id);
    assert.equal(task.state, 'succeeded');
    const result = (await readReceipt(task.receipt!, intent, f.owner.binding.id, f.owner.keys)).result as Record<string, JsonValue>;
    assert.equal(result.stdout, '[redacted]');
    assert.equal(result.exitCode, 0);
    const allowed = new Set(['PATH', 'LANG', 'LC_ALL', 'TZ', 'TERM', 'HOME', 'TMPDIR', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'TOKEN']);
    assert.equal(Object.keys(childEnvironment({ TOKEN: 'input' })).every(name => allowed.has(name)), true);
  } finally { await f.close(); }
});

test('HTTP応答の指定した値を、事前に承認した宛先へ暗号化して保存する', async () => {
  const f = await delegatedFixture();
  try {
    const output = { ...f.policy, id: crypto.randomUUID(), grants: [], producers: [{
      executor: f.executor.binding, runId: f.intent.id, expiresAt: f.intent.expiresAt, materialRevision: 1,
    }] };
    const approval = await approvePolicy(output, f.owner.binding, f.owner.keys);
    const operation = { ...f.operation, save: { '/token': { name: 'Captured', approval } } };
    const intent = { ...f.intent, operationDigest: await hash(operation) };
    await f.delegation.submit(f.owner.actor, await prepareRun(intent, operation, f.owner.keys));
    const executor = new Executor(f.environment, f.executor.keys, f.broker, new MemoryJournal(), {
      async send() { return { status: 200, headers: {}, body: encode('{"token":"captured-secret"}') }; },
    }, new CommandProcess({ isolation: 'process' }));
    await executor.tick();
    const task = await f.delegation.get(f.owner.actor, intent.id);
    assert.equal(task.state, 'succeeded');
    assert.deepEqual((await readReceipt(task.receipt!, intent, f.owner.binding.id, f.owner.keys)).result,
      { status: 200, saved: { Captured: output.id } });
    const saved = await f.custody.read(f.owner.actor, output.id);
    assert.equal(decode(await reveal(saved.content, f.owner.binding, f.owner.keys.encryption)), 'captured-secret');
  } finally { await f.close(); }
});
