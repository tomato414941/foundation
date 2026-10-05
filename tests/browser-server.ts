import { fixture } from './support.js';
import { MemoryObjects, MemoryPayments, MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';

const fixtureData = await fixture();
const origin = 'http://localhost:3458';
const context = await createContext({ ...fixtureData.config, origin, FOUNDATION_ORIGIN: origin, FOUNDATION_PORT: 3458 }, {
  db: fixtureData.db, mailer: fixtureData.mailer, storage: new MemoryObjects(), payments: new MemoryPayments(), runner: new MemoryRunner(),
  transport: { async send(request) { return { status: 200, headers: { 'content-type': 'application/json' }, body: new TextEncoder().encode(JSON.stringify({ message: 'Hello from the test service', method: request.method })) }; } },
});
const app = await buildApp(context);
app.get<{ Params: { address: string } }>('/__test/mail/:address', async request => ({ link: fixtureData.mailer.sent.findLast(item => item.address === request.params.address)?.link ?? null }));
app.post<{ Body: { principalId: string } }>('/__test/payment', async request => { await context.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,$2,'active') ON CONFLICT(principal_id) DO UPDATE SET status='active'", [request.body.principalId, 'customer-' + request.body.principalId]); return { ok: true }; });
const worker = new Worker(context, error => app.log.error(error));
await app.listen({ host: '127.0.0.1', port: 3458 }); worker.start();
let closing = false;
async function close() { if (closing) return; closing = true; await worker.stop(); await app.close(); await fixtureData.close(); }
process.once('SIGTERM', () => { void close(); }); process.once('SIGINT', () => { void close(); });
