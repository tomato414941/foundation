import { fixture } from './support.js';
import { MemoryObjects, MemoryPayments, MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Worker } from '../server/worker.js';
import { createCipheriv, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const fixtureData = await fixture();
const origin = 'http://localhost:3458';
const context = await createContext(
  { ...fixtureData.config, origin, FOUNDATION_ORIGIN: origin, FOUNDATION_PORT: 3458 },
  {
    db: fixtureData.db,
    mailer: fixtureData.mailer,
    storage: new MemoryObjects(),
    payments: new MemoryPayments(),
    runner: new MemoryRunner(),
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
app.post<{ Body: { principalId: string; prf: string } }>('/__test/existing-encryption', async (request) => {
  const sample = JSON.parse(await readFile(new URL('./fixtures/legacy-encryption.json', import.meta.url), 'utf8'));
  const { principalId, prf } = request.body;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', hkdfSync('sha256', Buffer.from(prf, 'base64url'), '', 'foundation-key', 32), iv);
  const content = Buffer.concat([cipher.update(Buffer.from(sample.privateKey.d, 'base64url')), cipher.final()]);
  const wrapped = Buffer.concat([iv, cipher.getAuthTag(), content]).toString('base64url');
  const id = randomUUID();
  const sealed = {
    ...sample.sealed,
    aad: Buffer.from('resource:' + id).toString('base64url'),
    recipients: sample.sealed.recipients.map((recipient: { header: Record<string, unknown> }) => ({
      ...recipient, header: { ...recipient.header, kid: principalId },
    })),
  };
  await context.db.transaction(async client => {
    await client.query('UPDATE principals SET public_key=$2 WHERE id=$1', [principalId, JSON.stringify(sample.publicKey)]);
    await client.query("UPDATE credentials SET private_wrap=$2 WHERE principal_id=$1 AND kind='passkey'", [principalId, 'x25519:' + wrapped]);
    await client.query("INSERT INTO resources(id,owner_id,kind,name,data,sealed) VALUES($1,$2,'secret','Existing secret',$3,$4)", [
      id, principalId, JSON.stringify({ bytes: Buffer.byteLength(sample.plaintext), recipients: [principalId] }), JSON.stringify(sealed),
    ]);
  });
  return { id, plaintext: sample.plaintext };
});
const worker = new Worker(context, (error) => app.log.error(error));
try {
  await app.listen({ host: '127.0.0.1', port: 3458 });
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
