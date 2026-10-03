import { randomUUID, createHmac, timingSafeEqual } from 'node:crypto';
import { fail } from './errors.mjs';

// Paying for what costs money: the principal that uses it pays, as a customer of Foundation's Stripe account. A
// payment method is set through Stripe's own page; what is used is recorded here first and then sent to Stripe's
// meters, where each month's free part and price are applied.
export const METERS = { compute: 'foundation_compute', storage: 'foundation_storage' };
const MEGABYTE = 1024 * 1024;
const day = at => new Date(at).toISOString().slice(0, 10);
const unavailable = () => fail(503, 'payment_unavailable', '現在、支払い方法を登録できません。');
// Subscription statuses in which use is charged and the higher ceilings hold. Any other - unpaid, canceled - is the
// free part again.
const CHARGEABLE = ['active', 'trialing'];

// Stripe's API speaks forms with nested keys: items[0][price]=...
function form(value, prefix, pairs = []) {
  if (value === undefined || value === null) return pairs;
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) form(item, prefix ? `${prefix}[${key}]` : key, pairs);
    return pairs;
  }
  pairs.push([prefix, String(value)]);
  return pairs;
}

export class Stripe {
  constructor({ key = '', computePrice = '', storagePrice = '', webhookSecret = '', fetcher = fetch } = {}) {
    Object.assign(this, { key, computePrice, storagePrice, webhookSecret, fetcher, enabled: Boolean(key && computePrice && storagePrice && webhookSecret) });
  }
  // What Stripe sends is signed with the endpoint's secret over the time and the body, and must be recent.
  verify(raw, header, now = Date.now()) {
    const parts = Object.fromEntries(String(header ?? '').split(',').map(part => part.split('=')).filter(pair => pair.length === 2));
    const signed = Number(parts.t), given = Buffer.from(parts.v1 ?? '', 'hex');
    const expected = createHmac('sha256', this.webhookSecret).update(`${parts.t}.${raw}`).digest();
    if (!Number.isInteger(signed) || Math.abs(now / 1000 - signed) > 300 || given.length !== expected.length || !timingSafeEqual(given, expected)) fail(400, 'invalid_signature', '署名を確認できませんでした。');
    try { return JSON.parse(raw); } catch { fail(400, 'invalid_signature', '署名を確認できませんでした。'); }
  }
  async call(method, path, params = {}, { idempotency } = {}) {
    const query = method === 'GET' ? '?' + new URLSearchParams(form(params)) : '';
    let response;
    try {
      response = await this.fetcher('https://api.stripe.com' + path + query, { method, redirect: 'error', signal: AbortSignal.timeout(20_000),
        headers: { authorization: 'Bearer ' + this.key, ...(method === 'GET' ? {} : { 'content-type': 'application/x-www-form-urlencoded' }), ...(idempotency ? { 'idempotency-key': idempotency } : {}) },
        ...(method === 'GET' ? {} : { body: new URLSearchParams(form(params)).toString() }) });
    } catch { fail(503, 'payment_unavailable', '支払いサービスに接続できませんでした。時間をおいてお試しください。'); }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) fail(response.status >= 500 ? 503 : 502, 'payment_unavailable', '支払いサービスが処理できませんでした。時間をおいてお試しください。');
    return data;
  }
}

export class Payments {
  constructor(store, stripe) { Object.assign(this, { store, db: store.db, stripe, sending: null }); }
  account(principalId) { return this.db.prepare('SELECT * FROM payment_accounts WHERE principal_id=?').get(principalId); }
  // Whether a principal can stand as a payer: it has registered a payment method here, so there is someone to charge.
  // Anyone may make a principal and nobody has to say who they are; what costs money needs a payer.
  payer(principalId) { return Boolean(this.account(principalId)?.subscription_id); }
  // Who pays for a principal's use: the one that took it on (a payer line), else its owner's payer, else itself if it
  // is a payer, else nobody (null). The free part and the ceiling are counted for the payer, over all it pays for; a
  // principal with no payer keeps secrets and acts for others, and uses nothing metered in its own name.
  payerOf(principalId, seen = new Set()) {
    if (seen.has(principalId)) return this.payer(principalId) ? principalId : null;
    seen.add(principalId);
    const payer = this.db.prepare("SELECT subject_id FROM relations WHERE relation='payer' AND object_type='principal' AND object_id=? ORDER BY created_at LIMIT 1").get(principalId)?.subject_id;
    if (payer) return this.payerOf(payer, seen);
    const owner = this.db.prepare("SELECT subject_id FROM relations WHERE relation='owner' AND object_type='principal' AND object_id=? ORDER BY created_at LIMIT 1").get(principalId)?.subject_id;
    if (owner) return this.payerOf(owner, seen);
    return this.payer(principalId) ? principalId : null;
  }
  // Everyone a payer pays for, itself included.
  family(payerId) { return payerId === null ? [] : this.db.prepare('SELECT id FROM principals').all().map(row => row.id).filter(id => this.payerOf(id) === payerId); }
  // What is metered is refused where nobody pays for it.
  needsPayer(principalId, what) { if (this.payerOf(principalId) === null) fail(402, 'payer_required', what + 'には支払い方法の登録が必要です。登録すると無料枠から使えます。'); }
  // Whether a principal's use can be charged: its payer has a payment method and a subscription to charge it to.
  paying(principalId) { const payer = this.payerOf(principalId); if (payer === null) return false; const row = this.account(payer); return Boolean(row?.subscription_id && CHARGEABLE.includes(row.status)); }
  view(principalId) { return { available: this.stripe.enabled, paying: this.paying(principalId), payer: this.payerOf(principalId) }; }

  // Setting a payment method: Stripe's page, for this principal's customer (made the first time).
  async setup(principalId, { origin, email }) {
    if (!this.stripe.enabled) unavailable();
    let row = this.account(principalId);
    if (!row) {
      const customer = await this.stripe.call('POST', '/v1/customers', { ...(email ? { email } : {}), metadata: { principal_id: principalId } }, { idempotency: 'customer:' + principalId });
      this.db.prepare('INSERT OR IGNORE INTO payment_accounts (principal_id,customer_id,created_at) VALUES (?,?,?)').run(principalId, customer.id, Date.now());
      row = this.account(principalId);
    }
    const session = await this.stripe.call('POST', '/v1/checkout/sessions', { mode: 'setup', currency: 'jpy', customer: row.customer_id,
      success_url: origin + '/account?payment={CHECKOUT_SESSION_ID}', cancel_url: origin + '/account' });
    return session.url;
  }
  // Coming back from it: the page's session must be this customer's and finished. Its payment method becomes the
  // customer's, and the first time, use starts to be charged to a subscription.
  async complete(principalId, sessionId) {
    if (!this.stripe.enabled) unavailable();
    const row = this.account(principalId);
    if (!row || typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{1,200}$/.test(sessionId)) fail(400, 'invalid_payment', '支払い方法の登録を確認できませんでした。');
    const session = await this.stripe.call('GET', '/v1/checkout/sessions/' + sessionId, { expand: ['setup_intent'] });
    const method = session.setup_intent?.payment_method;
    if (session.customer !== row.customer_id || session.mode !== 'setup' || session.status !== 'complete' || typeof method !== 'string') fail(400, 'invalid_payment', '支払い方法の登録を確認できませんでした。');
    await this.stripe.call('POST', '/v1/customers/' + row.customer_id, { invoice_settings: { default_payment_method: method } });
    if (!row.subscription_id || !CHARGEABLE.includes(row.status)) {
      const subscription = await this.stripe.call('POST', '/v1/subscriptions', { customer: row.customer_id, items: [{ price: this.stripe.computePrice }, { price: this.stripe.storagePrice }] },
        { idempotency: 'subscription:' + principalId + ':' + (row.subscription_id ?? '') });
      this.db.prepare('UPDATE payment_accounts SET subscription_id=?, status=? WHERE principal_id=?').run(subscription.id, subscription.status, principalId);
    }
    return this.view(principalId);
  }

  // What was used: a machine's seconds weighted by its size, recorded when it stops.
  computed(principalId, seconds, at) {
    if (seconds > 0 && this.paying(principalId)) this.db.prepare('INSERT INTO meter_events (id,principal_id,meter,value,at) VALUES (?,?,?,?,?)').run(randomUUID(), this.payerOf(principalId), 'compute', seconds, at);
  }
  // What is stored, once a day for each principal that pays, in megabytes.
  stored(principalId, bytes, at) {
    this.db.prepare('INSERT OR IGNORE INTO meter_events (id,principal_id,meter,value,at) VALUES (?,?,?,?,?)')
      .run('storage:' + principalId + ':' + day(at), principalId, 'storage', Math.ceil(bytes / MEGABYTE), at);
  }
  payers() { return this.db.prepare(`SELECT principal_id FROM payment_accounts WHERE subscription_id IS NOT NULL AND status IN (${CHARGEABLE.map(() => '?').join(',')})`).all(...CHARGEABLE).map(row => row.principal_id); }
  // What Stripe says of a subscription: when payment fails or it ends, use goes back to the free part.
  changed(event) {
    if (!event?.type?.startsWith('customer.subscription.') || typeof event.data?.object?.id !== 'string') return;
    const status = event.type === 'customer.subscription.deleted' ? 'canceled' : String(event.data.object.status ?? '');
    this.db.prepare('UPDATE payment_accounts SET status=? WHERE subscription_id=?').run(status, event.data.object.id);
  }
  // Sending what is recorded, oldest first. Stripe keeps one event per identifier, so sending again after a failure
  // never charges twice.
  send() {
    if (!this.stripe.enabled || this.sending) return this.sending;
    this.sending = (async () => {
      const pending = this.db.prepare('SELECT e.*, a.customer_id FROM meter_events e JOIN payment_accounts a ON a.principal_id=e.principal_id WHERE e.sent_at IS NULL ORDER BY e.at LIMIT 100').all();
      for (const event of pending) {
        if (event.value > 0) await this.stripe.call('POST', '/v1/billing/meter_events', { event_name: METERS[event.meter], identifier: event.id,
          timestamp: Math.floor(event.at / 1000), payload: { stripe_customer_id: event.customer_id, value: event.value } });
        this.db.prepare('UPDATE meter_events SET sent_at=? WHERE id=?').run(Date.now(), event.id);
      }
    })().finally(() => { this.sending = null; });
    return this.sending;
  }
}
