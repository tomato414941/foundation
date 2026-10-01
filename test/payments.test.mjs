import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { fixture, fakeStripe, USER_A, USER_B } from './helpers.mjs';

test('支払い方法を登録すると、Stripeの顧客と契約ができ、無料枠より多く使えるようになる', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  assert.deepEqual((await f.request('/v1/payment')).json.payment, { available: true, paying: false });
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 36_000, 'the free part, before paying');
  const started = await f.request('/v1/payment/setup', { method: 'POST', data: {} });
  assert.equal(started.status, 200, started.text);
  assert.equal(started.json.url, 'https://checkout.stripe.com/c/pay/cs_test_1');
  const page = fake.calls.find(call => call.path === '/v1/checkout/sessions');
  assert.equal(page.body.mode, 'setup');
  assert.equal(page.body.success_url, f.base + '/account?payment={CHECKOUT_SESSION_ID}');
  const done = await f.request('/v1/payment/complete', { method: 'POST', data: { session_id: 'cs_test_1' } });
  assert.equal(done.status, 200, done.text);
  assert.deepEqual(done.json.payment, { available: true, paying: true });
  assert.deepEqual(fake.calls.find(call => call.path === '/v1/subscriptions').body, { customer: 'cus_1', 'items[0][price]': 'price_compute', 'items[1][price]': 'price_storage' });
  assert.equal(fake.calls.find(call => call.path === '/v1/customers/cus_1').body['invoice_settings[default_payment_method]'], 'pm_1');
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 360_000);
});

test('ほかの顧客のものや終わっていない支払い方法の登録は受け付けない', async t => {
  for (const options of [{ otherCustomer: true }, { sessionStatus: 'open' }]) {
    const fake = fakeStripe(options), f = await fixture(t, { stripe: fake.stripe });
    await f.request('/v1/payment/setup', { method: 'POST', data: {} });
    const refused = await f.request('/v1/payment/complete', { method: 'POST', data: { session_id: 'cs_test_1' } });
    assert.equal(refused.status, 400, JSON.stringify(options));
    assert.equal((await f.request('/v1/payment')).json.payment.paying, false);
  }
});

test('Stripeの用意がなければ支払い方法は登録できず、誰もが無料枠で止まる', async t => {
  const f = await fixture(t);
  assert.deepEqual((await f.request('/v1/payment')).json.payment, { available: false, paying: false });
  assert.equal((await f.request('/v1/payment/setup', { method: 'POST', data: {} })).status, 503);
  f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)').run(USER_A, new Date().toISOString().slice(0, 7), 36_000);
  assert.throws(() => f.app.environments.within(USER_A), { status: 402, code: 'payment_required' });
});

test('支払う人が使った計算時間と保存量を記録し、Stripeへは1件につき一度だけ送る', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  await f.request('/v1/payment/setup', { method: 'POST', data: {} });
  await f.request('/v1/payment/complete', { method: 'POST', data: { session_id: 'cs_test_1' } });
  const at = Date.now();
  f.app.payments.computed(USER_A, 120, at);
  f.app.payments.stored(USER_A, 3 * 1024 * 1024 + 1, at);
  f.app.payments.stored(USER_A, 5 * 1024 * 1024, at);
  await f.app.payments.send();
  await f.app.payments.send();
  const sent = [...fake.meterEvents.values()];
  assert.equal(fake.calls.filter(call => call.path === '/v1/billing/meter_events').length, 2);
  assert.deepEqual(sent.map(event => [event.event_name, event['payload[stripe_customer_id]'], event['payload[value]']]).sort(),
    [['foundation_compute', 'cus_1', '120'], ['foundation_storage', 'cus_1', '4']]);
});

test('支払っていない人の使った分は記録しない', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  f.app.payments.computed(USER_A, 120, Date.now());
  await f.app.payments.send();
  assert.equal(fake.meterEvents.size, 0);
});

async function paying(f) {
  await f.request('/v1/payment/setup', { method: 'POST', data: {} });
  await f.request('/v1/payment/complete', { method: 'POST', data: { session_id: 'cs_test_1' } });
}
const signed = (body, secret = 'whsec_test', at = Math.floor(Date.now() / 1000)) => ({ 't': at, 'v1': createHmac('sha256', secret).update(`${at}.${body}`).digest('hex') });
const notify = (f, event, signature = signed(JSON.stringify(event))) => f.request('/v1/payment/events', { method: 'POST', anonymous: true, raw: JSON.stringify(event), type: 'application/json',
  headers: { 'stripe-signature': `t=${signature.t},v1=${signature.v1}` } });

test('支払いに失敗した、または解約されたとStripeが知らせると、無料枠に戻る', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  await paying(f);
  const changed = await notify(f, { type: 'customer.subscription.updated', data: { object: { id: 'sub_1', status: 'past_due' } } });
  assert.equal(changed.status, 200, changed.text);
  assert.equal((await f.request('/v1/payment')).json.payment.paying, false);
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 36_000);
  await notify(f, { type: 'customer.subscription.updated', data: { object: { id: 'sub_1', status: 'active' } } });
  assert.equal((await f.request('/v1/payment')).json.payment.paying, true);
  await notify(f, { type: 'customer.subscription.deleted', data: { object: { id: 'sub_1', status: 'active' } } });
  assert.equal((await f.request('/v1/payment')).json.payment.paying, false);
});

test('Stripeの秘密で署名されていない知らせや古い知らせは受け付けない', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  await paying(f);
  const event = { type: 'customer.subscription.deleted', data: { object: { id: 'sub_1' } } };
  assert.equal((await notify(f, event, signed(JSON.stringify(event), 'whsec_other'))).status, 400);
  assert.equal((await notify(f, event, signed(JSON.stringify(event), 'whsec_test', Math.floor(Date.now() / 1000) - 3600))).status, 400);
  assert.equal((await f.request('/v1/payment')).json.payment.paying, true);
});

test('支払っていない人たちの計算時間は、全体でも上限を超えない', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  const month = new Date().toISOString().slice(0, 7), use = f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)');
  f.app.principals.ensure(USER_B);
  use.run(USER_B, month, 360_000);
  assert.throws(() => f.app.environments.within(USER_A), { status: 402, code: 'payment_required' }, 'the free part is used up for everyone');
  await paying(f);
  f.app.environments.within(USER_A);
});
