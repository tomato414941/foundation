import { randomUUID } from 'node:crypto';
import Stripe from 'stripe';
import type { Database, Queryable } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import type { Configuration } from './config.js';
import type { Audit } from './audit.js';
import { fail, required } from './errors.js';

export interface PaymentAccount {
  customerId: string;
  subscriptionId: string | null;
  status: string;
}
export interface PaymentEvent {
  id: string;
  customerId: string;
  subscriptionId: string | null;
  status: string;
}
export interface PaymentProvider {
  readonly enabled: boolean;
  customer(id: string, name: string): Promise<string>;
  checkout(customerId: string, principalId: string): Promise<string>;
  portal(customerId: string): Promise<string>;
  event(body: Buffer, signature: string): Promise<PaymentEvent | null>;
  meter(event: {
    id: string;
    customerId: string;
    meter: 'compute' | 'storage';
    amount: number;
    createdAt: Date;
  }): Promise<void>;
}
export class StripePayments implements PaymentProvider {
  readonly stripe: Stripe | null;
  readonly enabled: boolean;
  constructor(readonly config: Configuration) {
    this.enabled = Boolean(
      config.FOUNDATION_BILLING_MODE === 'required' &&
        config.STRIPE_SECRET_KEY &&
        config.STRIPE_COMPUTE_PRICE &&
        config.STRIPE_STORAGE_PRICE &&
        config.STRIPE_WEBHOOK_SECRET,
    );
    this.stripe = this.enabled
      ? new Stripe(config.STRIPE_SECRET_KEY, { maxNetworkRetries: 2, timeout: 20_000 })
      : null;
  }
  private client() {
    if (!this.stripe) fail(503, 'payments_unavailable', 'Payments are not configured.');
    return this.stripe;
  }
  async customer(id: string, name: string) {
    return (
      await this.client().customers.create(
        { name, metadata: { foundation_principal: id } },
        { idempotencyKey: 'foundation-customer-' + id },
      )
    ).id;
  }
  async checkout(customerId: string, principalId: string) {
    const result = await this.client().checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      client_reference_id: principalId,
      subscription_data: { metadata: { foundation_principal: principalId } },
      line_items: [{ price: this.config.STRIPE_COMPUTE_PRICE }, { price: this.config.STRIPE_STORAGE_PRICE }],
      success_url: this.config.origin + '/p/' + principalId + '/settings/billing?payment=complete',
      cancel_url: this.config.origin + '/p/' + principalId + '/settings/billing',
      payment_method_collection: 'always',
    });
    return required(result.url, 'The payment page could not be opened.');
  }
  async portal(customerId: string) {
    return (
      await this.client().billingPortal.sessions.create({
        customer: customerId,
        return_url: this.config.origin + '/account',
      })
    ).url;
  }
  async event(body: Buffer, signature: string): Promise<PaymentEvent | null> {
    let event: Stripe.Event;
    try {
      event = this.client().webhooks.constructEvent(body, signature, this.config.STRIPE_WEBHOOK_SECRET);
    } catch {
      fail(400, 'invalid_signature', 'The webhook signature could not be verified.');
    }
    if (
      ![
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
        'checkout.session.completed',
      ].includes(event.type)
    )
      return null;
    let subscriptionId: string | null = null,
      customerId: string;
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object as Stripe.Checkout.Session;
      if (session.mode !== 'subscription' || !session.customer || !session.subscription) return null;
      customerId = typeof session.customer === 'string' ? session.customer : session.customer.id;
      subscriptionId =
        typeof session.subscription === 'string' ? session.subscription : session.subscription.id;
    } else {
      const value = event.data.object as Stripe.Subscription;
      customerId = typeof value.customer === 'string' ? value.customer : value.customer.id;
      subscriptionId = value.id;
    }
    // Fetch current state so a delayed webhook cannot restore a cancelled subscription.
    const subscription = await this.client().subscriptions.retrieve(subscriptionId);
    const customer =
      typeof subscription.customer === 'string' ? subscription.customer : subscription.customer.id;
    if (customer !== customerId)
      fail(400, 'invalid_subscription', 'The subscription does not belong to this account.');
    const prices = new Set(subscription.items.data.map((item) => item.price.id));
    const status =
      prices.has(this.config.STRIPE_COMPUTE_PRICE) && prices.has(this.config.STRIPE_STORAGE_PRICE)
        ? subscription.status
        : 'invalid';
    return { id: event.id, customerId, subscriptionId, status };
  }
  async meter(event: {
    id: string;
    customerId: string;
    meter: 'compute' | 'storage';
    amount: number;
    createdAt: Date;
  }) {
    await this.client().billing.meterEvents.create(
      {
        event_name:
          event.meter === 'compute' ? this.config.STRIPE_COMPUTE_METER : this.config.STRIPE_STORAGE_METER,
        identifier: event.id,
        timestamp: Math.floor(event.createdAt.getTime() / 1000),
        payload: { stripe_customer_id: event.customerId, value: String(event.amount) },
      },
      { idempotencyKey: event.id },
    );
  }
}
export class Billing {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly provider: PaymentProvider,
    readonly config: Configuration,
  ) {}
  async payer(principalId: string, connection: Queryable = this.db.pool) {
    const chain = await this.db.all<{ id: string; depth: number }>(
      `WITH RECURSIVE family(id,depth,visited) AS (
      SELECT $1::uuid,0,ARRAY[$1::uuid] UNION ALL
      SELECT r.subject_id,f.depth+1,f.visited||r.subject_id FROM family f CROSS JOIN LATERAL (
        SELECT subject_id FROM relations WHERE principal_id=f.id AND relation IN ('payer','owner') ORDER BY CASE relation WHEN 'payer' THEN 0 ELSE 1 END,created_at,id LIMIT 1
      ) r WHERE NOT r.subject_id=ANY(f.visited) AND f.depth<32
    ) SELECT id,depth FROM family ORDER BY depth DESC`,
      [principalId],
      connection,
    );
    return chain[0]?.id ?? principalId;
  }
  async payment(actor: Actor, principalId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'read');
    const id = await this.payer(principalId),
      principal = required(
        await this.db.one<{ id: string; name: string }>('SELECT id,name FROM principals WHERE id=$1', [id]),
      );
    const account = await this.db.one<{ status: string }>(
      'SELECT status FROM payment_accounts WHERE principal_id=$1',
      [id],
    );
    return {
      available: this.provider.enabled,
      required: this.config.FOUNDATION_BILLING_MODE === 'required',
      active: ['active', 'trialing'].includes(account?.status ?? ''),
      payer: principal,
    };
  }
  async requirePayment(principalId: string, connection: Queryable = this.db.pool) {
    const id = await this.payer(principalId, connection);
    if (this.config.FOUNDATION_BILLING_MODE === 'included') return id;
    if (!this.provider.enabled) fail(503, 'payments_unavailable', 'Payments are not configured.');
    const account = await this.db.one<{ status: string }>(
        'SELECT status FROM payment_accounts WHERE principal_id=$1',
        [id],
        connection,
      );
    if (!account || !['active', 'trialing'].includes(account.status))
      fail(402, 'payment_required', 'Add a payment method to use storage and environments.');
    return id;
  }
  async usage(principalId: string, connection: Queryable = this.db.pool) {
    const limits = await this.db.one<{ compute_seconds: string; storage_bytes: string }>(
      'SELECT compute_seconds,storage_bytes FROM usage_limits WHERE principal_id=$1',
      [principalId],
      connection,
    );
    const storage = await this.db.one<{ bytes: string }>(
      `SELECT coalesce(sum(CASE kind WHEN 'object' THEN (data->>'size')::bigint WHEN 'variable' THEN (data->>'bytes')::bigint ELSE 0 END),0) bytes FROM resources WHERE owner_id=$1`,
      [principalId],
      connection,
    );
    const compute = await this.db.one<{ seconds: string }>(
      "SELECT coalesce(sum(amount),0) seconds FROM billing_events WHERE principal_id=$1 AND meter='compute' AND created_at>=date_trunc('month',now())",
      [principalId],
      connection,
    );
    return {
      storageBytes: Number(storage?.bytes ?? 0),
      storageLimit: Number(limits?.storage_bytes ?? 1_073_741_824),
      computeSeconds: Number(compute?.seconds ?? 0),
      computeLimit: Number(limits?.compute_seconds ?? 3600),
      month: new Date().toISOString().slice(0, 7),
    };
  }
  async reserve(principalId: string, kind: 'storage' | 'compute', amount: number, connection: Queryable) {
    if (this.config.FOUNDATION_BILLING_MODE === 'included') {
      await connection.query('SELECT pg_advisory_xact_lock(736023746)');
      await this.reserveIncluded(kind, amount, connection);
    }
    await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
    await this.requirePayment(principalId, connection);
    const usage = await this.usage(principalId, connection);
    if (kind === 'storage' && usage.storageBytes + amount > usage.storageLimit)
      fail(409, 'storage_limit', 'Increase the storage limit or remove unused files.');
    if (kind === 'compute') {
      const reserved = await this.db.one<{ seconds: string }>(
        `SELECT coalesce(sum((data->'lifetime'->>'maxSeconds')::bigint * CASE data->>'size' WHEN 'large' THEN 4 WHEN 'medium' THEN 2 ELSE 1 END),0) seconds FROM resources WHERE owner_id=$1 AND kind='environment' AND data->>'state' IN ('starting','running','stopping')`,
        [principalId],
        connection,
      );
      if (usage.computeSeconds + Number(reserved?.seconds ?? 0) + amount > usage.computeLimit)
        fail(409, 'compute_limit', 'Increase the monthly compute limit or shorten the environment lifetime.');
    }
  }
  private async reserveIncluded(kind: 'storage' | 'compute', amount: number, connection: Queryable) {
    if (kind === 'storage' && amount > 0) {
      const total = await this.db.one<{ bytes: string }>(
        `SELECT coalesce(sum(CASE kind WHEN 'object' THEN (data->>'size')::bigint WHEN 'variable' THEN (data->>'bytes')::bigint ELSE 0 END),0) bytes FROM resources`,
        [],
        connection,
      );
      if (Number(total?.bytes ?? 0) + amount > this.config.FOUNDATION_INCLUDED_STORAGE_BYTES)
        fail(409, 'storage_capacity', 'The available storage capacity has been reached.');
    }
    if (kind === 'compute') {
      const active = await this.db.one<{ count: string; seconds: string }>(
        `SELECT count(*) count,coalesce(sum((data->'lifetime'->>'maxSeconds')::bigint * CASE data->>'size' WHEN 'large' THEN 4 WHEN 'medium' THEN 2 ELSE 1 END),0) seconds FROM resources WHERE kind='environment' AND data->>'state' IN ('starting','running','stopping')`,
        [],
        connection,
      );
      if (Number(active?.count ?? 0) >= this.config.FOUNDATION_INCLUDED_ENVIRONMENTS)
        fail(409, 'environment_capacity', 'All available environments are currently in use.');
      const used = await this.db.one<{ seconds: string }>(
        "SELECT coalesce(sum(amount),0) seconds FROM billing_events WHERE meter='compute' AND created_at>=date_trunc('month',now())",
        [],
        connection,
      );
      if (
        Number(used?.seconds ?? 0) + Number(active?.seconds ?? 0) + amount >
        this.config.FOUNDATION_INCLUDED_COMPUTE_SECONDS
      )
        fail(409, 'compute_capacity', 'The available monthly compute capacity has been reached.');
    }
  }
  async limits(actor: Actor, id: string, storageBytes: number, computeSeconds: number) {
    await this.authorization.requirePrincipal(actor, id, 'billing');
    await this.db.pool.query(
      'INSERT INTO usage_limits(principal_id,storage_bytes,compute_seconds) VALUES($1,$2,$3) ON CONFLICT(principal_id) DO UPDATE SET storage_bytes=$2,compute_seconds=$3',
      [id, storageBytes, computeSeconds],
    );
    await this.audit.record(id, actor.id, 'billing.limits', id, { storageBytes, computeSeconds });
  }
  async checkout(actor: Actor, id: string) {
    id = await this.payer(id);
    await this.authorization.requirePrincipal(actor, id, 'billing');
    return this.db.transaction(async (connection) => {
      const principal = required(
        await this.db.one<{ name: string }>(
          'SELECT name FROM principals WHERE id=$1 FOR UPDATE',
          [id],
          connection,
        ),
      );
      let account = await this.db.one<{ customer_id: string; status: string }>(
        'SELECT customer_id,status FROM payment_accounts WHERE principal_id=$1',
        [id],
        connection,
      );
      if (!account) {
        const customerId = await this.provider.customer(id, principal.name);
        await connection.query('INSERT INTO payment_accounts(principal_id,customer_id) VALUES($1,$2)', [
          id,
          customerId,
        ]);
        account = { customer_id: customerId, status: 'pending' };
      }
      return {
        url: await (['active', 'trialing'].includes(account.status)
          ? this.provider.portal(account.customer_id)
          : this.provider.checkout(account.customer_id, id)),
      };
    });
  }
  async portal(actor: Actor, id: string) {
    id = await this.payer(id);
    await this.authorization.requirePrincipal(actor, id, 'billing');
    const account = required(
      await this.db.one<{ customer_id: string }>(
        'SELECT customer_id FROM payment_accounts WHERE principal_id=$1',
        [id],
      ),
    );
    return { url: await this.provider.portal(account.customer_id) };
  }
  async webhook(body: Buffer, signature: string) {
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023750)');
      const event = await this.provider.event(body, signature);
      if (!event) return;
      const inserted = await connection.query(
        'INSERT INTO payment_webhooks(id) VALUES($1) ON CONFLICT DO NOTHING',
        [event.id],
      );
      if (!inserted.rowCount) return;
      await connection.query(
        'UPDATE payment_accounts SET subscription_id=$2,status=$3 WHERE customer_id=$1',
        [event.customerId, event.subscriptionId, event.status],
      );
    });
  }
  async record(
    principalId: string,
    meter: 'storage' | 'compute',
    amount: number,
    reference: string,
    connection: Queryable = this.db.pool,
  ) {
    if (!Number.isSafeInteger(amount) || amount < 0)
      throw new Error('Usage must be a nonnegative safe integer.');
    await connection.query(
      'INSERT INTO billing_events(id,reference,payer_id,principal_id,meter,amount) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(reference) DO NOTHING',
      [randomUUID(), reference, await this.payer(principalId, connection), principalId, meter, amount],
    );
  }
  async report() {
    if (!this.provider.enabled) return;
    for (let index = 0; index < 50; index++) {
      const sent = await this.db.transaction(async (connection) => {
        const event = await this.db.one<{
          id: string;
          customer_id: string;
          meter: 'compute' | 'storage';
          amount: string;
          created_at: Date;
        }>(
          `SELECT b.*,p.customer_id FROM billing_events b JOIN payment_accounts p ON p.principal_id=b.payer_id WHERE b.sent_at IS NULL ORDER BY b.created_at LIMIT 1 FOR UPDATE OF b SKIP LOCKED`,
          [],
          connection,
        );
        if (!event) return false;
        if (Number(event.amount) > 0)
          await this.provider.meter({
            id: event.id,
            customerId: event.customer_id,
            meter: event.meter,
            amount: Number(event.amount),
            createdAt: event.created_at,
          });
        await connection.query('UPDATE billing_events SET sent_at=now() WHERE id=$1', [event.id]);
        return true;
      });
      if (!sent) break;
    }
  }
  async measureStorage() {
    const bucket = new Date().toISOString().slice(0, 13);
    await this.db.transaction(async (connection) => {
      const inserted = await connection.query(
        "INSERT INTO system_settings(name,value) VALUES($1,'true') ON CONFLICT DO NOTHING",
        ['storage-meter:' + bucket],
      );
      if (!inserted.rowCount) return;
      const rows = await this.db.all<{ owner_id: string; bytes: string }>(
        `SELECT owner_id,sum((data->>'size')::bigint) bytes FROM resources WHERE kind='object' GROUP BY owner_id`,
        [],
        connection,
      );
      for (const row of rows)
        await this.record(
          row.owner_id,
          'storage',
          Number(row.bytes),
          'storage:' + bucket + ':' + row.owner_id,
          connection,
        );
    });
  }
}
