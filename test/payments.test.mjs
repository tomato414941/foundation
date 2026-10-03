import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { fixture, fakeStripe, USER_A, USER_B } from './helpers.mjs';

test('支払い方法を登録すると、Stripeの顧客と契約ができて自分の負担者になり、無料枠より多く使えるようになる', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe, payers: false });
  assert.deepEqual((await f.request('/v1/principals/me/payment')).json.payment, { available: true, paying: false, payer: null }, 'nobody pays for one that has registered nothing');
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 36_000, 'the free part, before paying');
  const started = await f.request('/v1/principals/me/payment', { method: 'POST', data: {} });
  assert.equal(started.status, 200, started.text);
  assert.equal(started.json.url, 'https://checkout.stripe.com/c/pay/cs_test_1');
  const page = fake.calls.find(call => call.path === '/v1/checkout/sessions');
  assert.equal(page.body.mode, 'setup');
  assert.equal(page.body.success_url, f.base + '/account?payment={CHECKOUT_SESSION_ID}');
  const done = await f.request('/v1/principals/me/payment', { method: 'PUT', data: { session_id: 'cs_test_1' } });
  assert.equal(done.status, 200, done.text);
  assert.deepEqual(done.json.payment, { available: true, paying: true, payer: USER_A });
  assert.deepEqual(fake.calls.find(call => call.path === '/v1/subscriptions').body, { customer: 'cus_1', 'items[0][price]': 'price_compute', 'items[1][price]': 'price_storage' });
  assert.equal(fake.calls.find(call => call.path === '/v1/customers/cus_1').body['invoice_settings[default_payment_method]'], 'pm_1');
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 360_000);
});

test('ほかの顧客のものや終わっていない支払い方法の登録は受け付けない', async t => {
  for (const options of [{ otherCustomer: true }, { sessionStatus: 'open' }]) {
    const fake = fakeStripe(options), f = await fixture(t, { stripe: fake.stripe, payers: false });
    await f.request('/v1/principals/me/payment', { method: 'POST', data: {} });
    const refused = await f.request('/v1/principals/me/payment', { method: 'PUT', data: { session_id: 'cs_test_1' } });
    assert.equal(refused.status, 400, JSON.stringify(options));
    assert.equal((await f.request('/v1/principals/me/payment')).json.payment.paying, false);
  }
});

test('Stripeの用意がなければ支払い方法は登録できず、誰もが自分の負担者として無料枠で止まる', async t => {
  const f = await fixture(t, { payers: false });
  assert.deepEqual((await f.request('/v1/principals/me/payment')).json.payment, { available: false, paying: false, payer: USER_A }, 'with no way to register, nobody is asked to');
  const alone = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'alone' } });
  assert.equal(f.app.payments.payerOf(alone.json.principal.id), alone.json.principal.id);
  f.app.environments.within(alone.json.principal.id);
  assert.equal((await f.request('/v1/principals/me/payment', { method: 'POST', data: {} })).status, 503);
  f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)').run(USER_A, new Date().toISOString().slice(0, 7), 36_000);
  assert.throws(() => f.app.environments.within(USER_A), { status: 402, code: 'payment_required' });
});

test('支払う人が使った計算時間と保存量を記録し、Stripeへは1件につき一度だけ送る', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe, payers: false });
  await f.request('/v1/principals/me/payment', { method: 'POST', data: {} });
  await f.request('/v1/principals/me/payment', { method: 'PUT', data: { session_id: 'cs_test_1' } });
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
  // Through Stripe's page, as one who had registered nothing before.
  f.app.store.db.prepare('DELETE FROM payment_accounts WHERE principal_id=?').run(USER_A);
  await f.request('/v1/principals/me/payment', { method: 'POST', data: {} });
  await f.request('/v1/principals/me/payment', { method: 'PUT', data: { session_id: 'cs_test_1' } });
}
const signed = (body, secret = 'whsec_test', at = Math.floor(Date.now() / 1000)) => ({ 't': at, 'v1': createHmac('sha256', secret).update(`${at}.${body}`).digest('hex') });
const notify = (f, event, signature = signed(JSON.stringify(event))) => f.request('/v1/payment/events', { method: 'POST', anonymous: true, raw: JSON.stringify(event), type: 'application/json',
  headers: { 'stripe-signature': `t=${signature.t},v1=${signature.v1}` } });

test('支払いに失敗した、または解約されたとStripeが知らせると、無料枠に戻る', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe, payers: false });
  await paying(f);
  const changed = await notify(f, { type: 'customer.subscription.updated', data: { object: { id: 'sub_1', status: 'past_due' } } });
  assert.equal(changed.status, 200, changed.text);
  assert.equal((await f.request('/v1/principals/me/payment')).json.payment.paying, false);
  assert.equal(f.app.environments.usage(USER_A).limit_seconds, 36_000);
  await notify(f, { type: 'customer.subscription.updated', data: { object: { id: 'sub_1', status: 'active' } } });
  assert.equal((await f.request('/v1/principals/me/payment')).json.payment.paying, true);
  await notify(f, { type: 'customer.subscription.deleted', data: { object: { id: 'sub_1', status: 'active' } } });
  assert.equal((await f.request('/v1/principals/me/payment')).json.payment.paying, false);
});

test('Stripeの秘密で署名されていない知らせや古い知らせは受け付けない', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe, payers: false });
  await paying(f);
  const event = { type: 'customer.subscription.deleted', data: { object: { id: 'sub_1' } } };
  assert.equal((await notify(f, event, signed(JSON.stringify(event), 'whsec_other'))).status, 400);
  assert.equal((await notify(f, event, signed(JSON.stringify(event), 'whsec_test', Math.floor(Date.now() / 1000) - 3600))).status, 400);
  assert.equal((await f.request('/v1/principals/me/payment')).json.payment.paying, true);
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

test('持っている相手が使った分は持ち主の枠に数えられ、相手を増やしても無料枠は増えず、負担は引き受ける側だけが引ける', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe }), month = new Date().toISOString().slice(0, 7);
  const agent = await f.issueKey('box'), group = (await f.request('/v1/principals', { method: 'POST', data: { name: 'team', steward: true } })).json.principal;
  assert.equal((await f.request('/v1/principals/me/payment', { token: agent.token, anonymous: true })).json.payment.payer, USER_A, 'an owned principal is paid for by its owner');
  assert.equal(f.app.payments.payerOf(group.id), USER_A);
  f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)').run(agent.id, month, 20_000);
  f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)').run(group.id, month, 10_000);
  assert.equal(f.app.environments.usage(USER_A).used_seconds, 30_000, 'what those it pays for spent counts for the payer');
  assert.equal(f.app.environments.usage(agent.id).used_seconds, 30_000, 'and the same count is theirs');
  f.app.store.db.prepare('INSERT INTO compute_usage (principal_id,month,seconds) VALUES (?,?,?)').run(USER_A, month, 6_000);
  assert.throws(() => f.app.environments.within(agent.id), /無料枠の上限/, 'the free part is one, not one per principal');
  // Another person takes the group's costs on: only they can draw that line, and from then on the group counts for them.
  // One of its own (made by nobody here), or its costs would only roll up to this owner again.
  const sponsor = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'sponsor' } });
  assert.equal((await f.request('/v1/principals/' + sponsor.json.principal.id + '/relations', { method: 'POST', data: { relation: 'payer', object_type: 'principal', object_id: group.id } })).status, 403, 'not put on someone');
  // A sponsor acting as itself: it may give lines on the group only where it may relate there, so the group's steward lends it that first.
  f.app.principals.relate(sponsor.json.principal.id, 'relate_grant', 'principal', group.id);
  f.app.principals.relate(sponsor.json.principal.id, 'payment_grant', 'principal', group.id);
  const unbound = await f.request('/v1/principals/' + sponsor.json.principal.id + '/relations', { method: 'POST', token: sponsor.json.token, anonymous: true, data: { relation: 'payer', object_type: 'principal', object_id: group.id } });
  assert.equal(unbound.status, 402); assert.equal(unbound.json.error.code, 'payer_required', 'one with no payment method cannot take costs on');
  f.bind(sponsor.json.principal.id);
  const taken = await f.request('/v1/principals/' + sponsor.json.principal.id + '/relations', { method: 'POST', token: sponsor.json.token, anonymous: true, data: { relation: 'payer', object_type: 'principal', object_id: group.id } });
  assert.equal(taken.status, 201, taken.text);
  assert.equal(f.app.payments.payerOf(group.id), sponsor.json.principal.id);
  assert.equal(f.app.environments.usage(USER_A).used_seconds, 26_000, 'the group no longer counts for the maker');
  assert.equal(f.app.environments.usage(group.id).used_seconds, 10_000, 'but for its sponsor');
  assert.equal((await f.request('/v1/principals/' + group.id + '/payment', { token: sponsor.json.token, anonymous: true })).json.payment.payer, sponsor.json.principal.id, 'the payer may see the group\'s payment');
});

test('支払い方法のないプリンシパルには負担者がおらず、自分の名ではエンバイロメントもファイルも使えず、支払い方法を登録するか誰かに引き取られると負担者ができる', async t => {
  const fake = fakeStripe(), f = await fixture(t, { stripe: fake.stripe });
  // One that came by itself: nobody made it, nobody pays for it.
  const alone = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'alone' } });
  const as = { token: alone.json.token, anonymous: true };
  assert.deepEqual((await f.request('/v1/principals/me/payment', as)).json.payment, { available: true, paying: false, payer: null });
  assert.throws(() => f.app.environments.within(alone.json.principal.id), { status: 402, code: 'payer_required' });
  assert.throws(() => f.app.objects.fits(alone.json.principal.id, 1, 1), { status: 402, code: 'payer_required' });
  assert.equal(f.app.environments.usage(alone.json.principal.id).used_seconds, 0, 'its use is its own, counted for nobody');
  // What it makes is paid for by nobody too: the chain ends where it ends.
  const made = await f.request('/v1/principals', { ...as, method: 'POST', data: { name: 'made by alone', key: true } });
  assert.equal(made.status, 201, made.text);
  assert.equal(f.app.payments.payerOf(made.json.principal.id), null);
  // Registering a payment method makes it its own payer, and what it made is paid for by it.
  await f.request('/v1/principals/me/payment', { ...as, method: 'POST', data: {} });
  assert.equal((await f.request('/v1/principals/me/payment', { ...as, method: 'PUT', data: { session_id: 'cs_test_1' } })).json.payment.payer, alone.json.principal.id);
  f.app.environments.within(alone.json.principal.id);
  assert.equal(f.app.payments.payerOf(made.json.principal.id), alone.json.principal.id);
  // Another that came by itself and asks to be someone's agent: approving takes it in, so that person pays for it.
  const asking = await f.request('/v1/principals', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'asking' } });
  assert.throws(() => f.app.environments.within(asking.json.principal.id), { code: 'payer_required' });
  const asked = await f.request('/v1/requests', { token: asking.json.token, anonymous: true, method: 'POST', data: { authorization_details: [{ type: 'relation', relation: 'agent' }] } });
  assert.equal(asked.status, 201, asked.text);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { user_code: asked.json.request.user_code } })).status, 200);
  assert.equal(f.app.payments.payerOf(asking.json.principal.id), USER_A, 'the approver owns it now, and pays for it');
  f.app.environments.within(asking.json.principal.id);
});
