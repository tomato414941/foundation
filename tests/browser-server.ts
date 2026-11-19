import { fixture } from './support.js';
import { MemoryObjects, MemoryPayments } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';

const fixtureData = await fixture();
const port = Number(process.env.FOUNDATION_TEST_PORT ?? 3458);
const origin = 'http://localhost:' + port;
const context = await createContext(
  {
    ...fixtureData.config,
    origin,
    FOUNDATION_ORIGIN: origin,
    FOUNDATION_PORT: port,
    FOUNDATION_PROXY_ADDRESSES: '127.0.0.1',
  },
  {
    db: fixtureData.db,
    mailer: fixtureData.mailer,
    storage: new MemoryObjects(),
    payments: new MemoryPayments(),
    transport: {
      async send(request) {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: new TextEncoder().encode(
            JSON.stringify({ message: 'Hello from the test service', method: request.method }),
          ),
        };
      },
    },
  },
);
const app = await buildApp(context);
app.get('/__test/ready', async () => ({ pid: process.pid }));
// An item left as an earlier version of Foundation sealed it, which no device opens any more.
app.post<{ Params: { id: string } }>('/__test/earlier-form/:id', async request => {
  await context.db.pool.query("UPDATE resource_custody SET content=jsonb_set(content,'{policy,format}','2') WHERE resource_id=$1",
    [request.params.id]);
  return { ok: true };
});
// A week has passed since the principal asked for new keys.
app.post<{ Params: { id: string } }>('/__test/key-reset/:id/ready', async request => {
  await context.db.pool.query("UPDATE challenges SET data=data||jsonb_build_object('readyAt',$2::text) WHERE kind='key-reset' AND principal_id=$1",
    [request.params.id, new Date(Date.now() - 1000).toISOString()]);
  return { ok: true };
});
app.get<{ Params: { address: string } }>('/__test/mail/:address', async (request) => ({
  link: fixtureData.mailer.sent.findLast((item) => item.address === request.params.address)?.link ?? null,
}));
app.post<{ Body: { principalId: string } }>('/__test/payment', async (request) => {
  await context.db.pool.query(
    "INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active') ON CONFLICT(principal_id) DO UPDATE SET status='active'",
    [request.body.principalId, 'customer-' + request.body.principalId],
  );
  return { ok: true };
});
const worker = new Worker(context, (error) => app.log.error(error));
try {
  await app.listen({ host: '127.0.0.1', port });
} catch (error) {
  await app.close();
  await fixtureData.close();
  throw error;
}
worker.start();
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await worker.stop();
  await app.close();
  await fixtureData.close();
}
process.once('SIGTERM', () => {
  void close();
});
process.once('SIGINT', () => {
  void close();
});
