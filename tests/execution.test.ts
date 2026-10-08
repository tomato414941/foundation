import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { MemoryPayments, MemoryObjects, MemoryRunner } from './fakes.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { bindKeys, newIdentityKeys, signBinding } from '../shared/authority.js';
import { signEnvironment } from '../shared/execution.js';
import { CommandProcess } from '../runtime/command.js';
import { delegatedFixture } from './delegation-support.js';
import { randomBytes } from 'node:crypto';

test('配下のプリンシパルの支払いを支払元のアカウントで管理する', async (t) => {
  const f = await fixture(),
    c = await createContext(f.config, { db: f.db, payments: new MemoryPayments() });
  t.after(f.close);
  const owner = await f.person('Payer'),
    outsider = await f.person('Other account');
  const child = await f.principals.create('Project', null, owner.actor.id);
  const checkout = await c.billing.checkout(owner.actor, child.id);
  assert.equal(checkout.url, 'https://pay.example/checkout/customer-' + owner.actor.id);
  assert.equal((await c.billing.payment(owner.actor, child.id)).payer.id, owner.actor.id);
  await assert.rejects(c.billing.checkout(outsider.actor, child.id), { code: 'forbidden' });
  await f.db.pool.query("UPDATE payment_accounts SET status='active' WHERE principal_id=$1", [
    owner.actor.id,
  ]);
  assert.equal((await c.billing.payment(owner.actor, child.id)).active, true);
  assert.equal(
    (await c.billing.portal(owner.actor, child.id)).url,
    'https://pay.example/portal/customer-' + owner.actor.id,
  );
});

test('運営環境が自分の鍵で登録し、停止時に実行権を失効させて使用量を記録する', async t => {
  const f = await fixture(), payments = new MemoryPayments(), runner = new MemoryRunner();
  const c = await createContext(f.config, { db: f.db, mailer: f.mailer, payments, runner });
  t.after(f.close);
  const owner = await f.person();
  await f.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active')",
    [owner.actor.id, 'customer-' + owner.actor.id]);
  const row = await c.environments.create(owner.actor, owner.actor.id,
    EnvironmentInput.parse({ lifetime: { maxSeconds: 120, idleSeconds: 60 } }));
  assert.equal(row.data.state, 'starting');
  await c.environments.tick();
  const input = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(
    runner.machines.get(row.id)!.environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
  const keys = await newIdentityKeys(), binding = bindKeys(input.executorId, keys);
  const token = 'fk_' + randomBytes(32).toString('base64url');
  const enrollment = { bootstrap: input.bootstrap, binding: await signBinding(binding, keys), token };
  await c.environments.enroll(row.id, enrollment);
  await c.environments.enroll(row.id, { ...enrollment, binding: await signBinding(binding, keys) });
  const actor = (await c.authentication.authenticate(token))!;
  assert.equal(actor.id, input.executorId);
  const registration = await signEnvironment({ format: 1, id: row.id, origin: f.config.origin,
    ownerId: owner.actor.id, name: input.name, executor: binding, operatorId: actor.id,
    driver: 'managed', capabilities: ['http', 'command', 'connect'], callers: input.callers,
    isolation: 'container', commandImage: input.commandImage, revision: 1 }, keys);
  await c.delegation.register(actor, registration);
  assert.equal((await c.resources.get(row.id)).data.state, 'running');
  assert.equal((await c.delegation.environment(row.id)).registration.signature, registration.signature);
  await c.environments.stop(owner.actor, await c.resources.get(row.id));
  assert.equal(await c.authentication.authenticate(token), null);
  await f.db.pool.query("UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1", [row.id]);
  await c.environments.tick();
  assert.equal((await c.resources.get(row.id)).data.state, 'stopped');
  assert.equal(runner.machines.size, 0);
  assert.ok((await c.billing.usage(owner.actor.id)).computeSeconds >= 1);
  await c.billing.report(); await c.billing.report();
  assert.equal(payments.events.length, 1);
  assert.equal(runner.volumes.size, 1);
  await c.environments.remove(owner.actor, await c.resources.get(row.id));
  assert.equal(runner.volumes.size, 0);
});

test('ファイルを更新し、同時編集と保存容量の超過を拒否して現在の内容を保持する', async (t) => {
  const f = await fixture(),
    storage = new MemoryObjects(),
    c = await createContext(f.config, {
      db: f.db,
      mailer: f.mailer,
      payments: new MemoryPayments(),
      storage,
    });
  t.after(() => f.close());
  const owner = await f.person();
  await f.db.pool.query(
    "INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active')",
    [owner.actor.id, 'customer-' + owner.actor.id],
  );
  await c.billing.limits(owner.actor, owner.actor.id, 10, 3600);
  const first = await c.objects.upload(
    owner.actor,
    owner.actor.id,
    'note.txt',
    Buffer.from('one'),
    'text/plain',
  );
  const updated = await c.objects.upload(
    owner.actor,
    owner.actor.id,
    'note.txt',
    Buffer.from('two'),
    'text/plain',
    first,
  );
  await assert.rejects(
    () => c.objects.upload(owner.actor, owner.actor.id, 'note.txt', Buffer.from('old'), 'text/plain', first),
    { code: 'changed' },
  );
  assert.equal(Buffer.from(await c.objects.content(owner.actor, updated)).toString(), 'two');
  await assert.rejects(
    () =>
      c.objects.upload(
        owner.actor,
        owner.actor.id,
        'large.txt',
        Buffer.from('more than ten bytes'),
        'text/plain',
      ),
    { code: 'storage_limit' },
  );
  await c.objects.remove(owner.actor, updated);
  assert.equal(storage.files.size, 0);
});

test('支払い登録不要の利用枠を複数プリンシパルで共有し、保存容量と計算時間と同時起動数を制限する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const c = await createContext(
    {
      ...f.config,
      FOUNDATION_BILLING_MODE: 'included',
      FOUNDATION_INCLUDED_STORAGE_BYTES: 5,
      FOUNDATION_INCLUDED_COMPUTE_SECONDS: 180,
      FOUNDATION_INCLUDED_ENVIRONMENTS: 2,
    },
    { db: f.db, storage: new MemoryObjects(), runner: new MemoryRunner() },
  );
  const owners = [await f.person('First'), await f.person('Second')];
  assert.equal((await c.billing.payment(owners[0]!.actor, owners[0]!.actor.id)).required, false);
  const files = await Promise.allSettled(
    owners.map(({ actor }) => c.objects.upload(actor, actor.id, 'note.txt', Buffer.from('abc'), 'text/plain')),
  );
  assert.equal(files.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = files.find((result) => result.status === 'rejected');
  assert.ok(rejected?.status === 'rejected');
  assert.equal(rejected.reason.code, 'storage_capacity');
  for (const [index, result] of files.entries()) {
    if (result.status === 'fulfilled') {
      assert.equal(Buffer.from(await c.objects.content(owners[index]!.actor, result.value)).toString(), 'abc');
      await c.objects.remove(owners[index]!.actor, result.value);
    }
  }
  await c.objects.upload(owners[1]!.actor, owners[1]!.actor.id, 'all.txt', Buffer.from('abcde'), 'text/plain');
  const start = (index: number, seconds: number) => {
    const actor = owners[index]!.actor;
    return c.environments.create(
      actor,
      actor.id,
      EnvironmentInput.parse({ lifetime: { maxSeconds: seconds, idleSeconds: 60 } }),
    );
  };
  const first = await start(0, 120);
  await assert.rejects(start(1, 120), { code: 'compute_capacity' });
  const second = await start(1, 60);
  await assert.rejects(start(0, 60), { code: 'environment_capacity' });
  while (await c.environments.tick()) {}
  await c.environments.stop(owners[0]!.actor, await c.resources.get(first.id));
  await c.environments.stop(owners[1]!.actor, await c.resources.get(second.id));
  await f.db.pool.query('UPDATE environment_jobs SET retry_at=now()');
  while (await c.environments.tick()) {}
  assert.equal((await start(1, 120)).data.state, 'starting');
});

test('支払い登録が必要な環境では、支払いの準備が整ってからファイル保存を許可する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person(),
    storage = new MemoryObjects(),
    unconfigured = await createContext(f.config, { db: f.db, storage });
  assert.equal((await unconfigured.billing.payment(owner.actor, owner.actor.id)).required, true);
  await assert.rejects(
    unconfigured.objects.upload(owner.actor, owner.actor.id, 'note.txt', Buffer.from('abc'), 'text/plain'),
    { code: 'payments_unavailable' },
  );
  const configured = await createContext(f.config, { db: f.db, storage, payments: new MemoryPayments() });
  await assert.rejects(
    configured.objects.upload(owner.actor, owner.actor.id, 'note.txt', Buffer.from('abc'), 'text/plain'),
    { code: 'payment_required' },
  );
});

test('ワーカーが実行を一度だけ取得し、開始後の中断を確認待ちとして記録する', async t => {
  const f = await delegatedFixture();
  t.after(f.close);
  await f.delegation.submit(f.owner.actor, f.request);
  const claims = await Promise.all([f.delegation.claim(f.executor.actor, f.environment.manifest.id),
    f.delegation.claim(f.executor.actor, f.environment.manifest.id)]);
  assert.equal(claims.filter(Boolean).length, 1);
  await f.delegation.dispatch(f.executor.actor, f.intent.id, claims.find(Boolean)!.lease);
  await f.db.pool.query("UPDATE execution_tasks SET lease_until=now()-interval '1 minute' WHERE id=$1", [f.intent.id]);
  await f.delegation.recover();
  assert.equal((await f.delegation.get(f.owner.actor, f.intent.id)).state, 'uncertain');
});

test('実行用プログラムが環境変数とファイルと標準入力を渡し、終了結果を記録する', async () => {
  const result = await new CommandProcess({ isolation: 'process' }).execute({
    command: [process.execPath, '-e',
      "const fs=require('node:fs');process.stdout.write(process.env.VALUE+'|'+fs.readFileSync(process.env.DATA_FILE)+'|'+fs.readFileSync(0));"],
    stdin: 'input', timeoutSeconds: 10, environment: { VALUE: 'value' },
    files: { DATA_FILE: Buffer.from('file').toString('base64') },
  }, new AbortController().signal);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'value|file|input');
});

test('実行先が名乗るAWSの身元を実行環境に載せ、名乗らなくなれば外す', async t => {
  const f = await delegatedFixture();
  t.after(f.close);
  const awsPrincipal = 'arn:aws:iam::123456789012:role/own-server';
  const manifest = { format: 1 as const, id: crypto.randomUUID(), origin: f.config.origin, ownerId: f.executor.actor.id,
    name: 'Own server', executor: f.executor.binding, operatorId: f.executor.actor.id, driver: 'attached' as const,
    capabilities: ['http' as const, 'connect' as const], callers: [f.owner.binding], isolation: 'process' as const };
  await f.delegation.register(f.executor.actor, await signEnvironment({ ...manifest, awsPrincipal, revision: 1 }, f.executor.keys));
  assert.equal((await f.resources.get(manifest.id)).data.awsPrincipal, awsPrincipal);
  await f.delegation.register(f.executor.actor, await signEnvironment({ ...manifest, revision: 2 }, f.executor.keys));
  assert.equal((await f.resources.get(manifest.id)).data.awsPrincipal, undefined);
});
