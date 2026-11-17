import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { MemoryPayments, MemoryObjects } from './fakes.js';
import { ApprovalRequest, ObjectResource } from '../shared/contracts.js';
import { buildApp } from '../server/app.js';

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

test('オブジェクトを更新し、同時編集と保存容量の超過を拒否して現在の内容を保持する', async (t) => {
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
  await c.billing.limits(owner.actor, owner.actor.id, 10);
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
  assert.equal(storage.objects.size, 0);
});

test('通常のファイルアップロードと依頼からの更新を同じ利用者の権限と保存処理で行う', async t => {
  const f = await fixture(), c = await createContext(f.config, { db: f.db, mailer: f.mailer,
    payments: new MemoryPayments(), storage: new MemoryObjects() });
  const app = await buildApp(c); t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('File owner'), sender = await f.person('Sender');
  await f.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active')", [owner.actor.id, 'file-customer']);
  const headers = { authorization: 'Bearer ' + owner.token };
  const created = await app.inject({ method: 'POST', url: '/api/principals/' + owner.actor.id + '/objects?name=note.txt&contentType=text/plain',
    headers: { ...headers, 'content-type': 'application/octet-stream' }, payload: Buffer.from('one') });
  assert.equal(created.statusCode, 201, created.body);
  const file = ObjectResource.parse(created.json());
  const listed = await app.inject({ url: '/api/principals/' + owner.actor.id + '/resources?kind=object', headers });
  assert.equal(listed.statusCode, 200, listed.body);
  assert.deepEqual(listed.json().items.map((item: { id: string }) => item.id), [file.id]);
  const session = await app.inject({ url: '/api/session', headers });
  assert.equal(session.json().features.storage, true);
  const link = await app.inject({ method: 'POST', url: '/api/resources/' + file.id + '/link', headers, payload: {} });
  assert.equal(link.statusCode, 200, link.body);
  assert.equal(link.json().url, 'https://files.example/' + (await c.resources.get(file.id)).private_data + '?expires=900');
  const asked = await app.inject({ method: 'POST', url: '/api/requests', headers: { authorization: 'Bearer ' + sender.token },
    payload: { to: owner.actor.id, operations: [{ name: 'object.update', input: { id: file.id, version: file.version,
      contentType: 'text/plain', bytes: Buffer.from('two').toString('base64url') } }] } });
  assert.equal(asked.statusCode, 201, asked.body);
  const answered = await app.inject({ method: 'POST', url: '/api/requests/' + asked.json().id + '/approve', headers, payload: {} });
  assert.equal(answered.statusCode, 200, answered.body); assert.equal(ApprovalRequest.parse(answered.json()).state, 'accepted');
  const content = await app.inject({ url: '/api/resources/' + file.id + '/content', headers });
  assert.equal(content.body, 'two');
  const stale = await app.inject({ method: 'PUT', url: '/api/resources/' + file.id + '/content?version=' + file.version,
    headers: { ...headers, 'content-type': 'application/octet-stream' }, payload: Buffer.from('old') });
  assert.equal(stale.statusCode, 409, stale.body);
});

test('支払い登録不要の利用枠を複数プリンシパルで共有し、保存容量を制限する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const c = await createContext(
    {
      ...f.config,
      FOUNDATION_BILLING_MODE: 'included',
      FOUNDATION_INCLUDED_STORAGE_BYTES: 5,
    },
    { db: f.db, storage: new MemoryObjects() },
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
  await assert.rejects(
    c.objects.upload(owners[0]!.actor, owners[0]!.actor.id, 'more.txt', Buffer.from('a'), 'text/plain'),
    { code: 'storage_capacity' },
  );
});

test('支払い登録が必要な環境では、支払いの準備が整ってからオブジェクト保存を許可する', async (t) => {
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

