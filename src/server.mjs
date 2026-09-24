import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { builtins } from './connectors/index.mjs';
import { SupabaseAuth } from './auth.mjs';
import { Kms, resolveEncryptionKey } from './kms.mjs';
import { S3Space } from './objects.mjs';

const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;
const encryptionKey = await resolveEncryptionKey({ database: config.database, encryptionKey: config.encryptionKey, kms });
const auth = new SupabaseAuth(config.supabase);
const connectors = builtins();
const app = createApp({ database: config.database, encryptionKey, space: new S3Space(config.objects), publicOrigin: config.publicOrigin, owners: config.owners, trustedProxies: config.trustedProxies, auth, connectors });
app.server.listen(config.port, config.bind, () => {
  console.log(`Foundation: http://${config.bind}:${config.port}`);
  console.log(`Encryption key: ${kms ? 'wrapped by KMS ' + config.kms.keyId : 'plaintext key file or variable'}`);
  if (config.publicOrigin) console.log(`Private preview: ${config.publicOrigin}`);
  console.log(`Supabase Auth: ${auth.enabled ? 'configured' : 'not configured'}`);
  console.log(`Email login: ${auth.emailEnabled ? 'enabled' : 'disabled'}; Object space: ${config.objects.bucket || 'not configured'}`);
  console.log('Connectors: ' + connectors.map(connector => `${connector.id}: ${connector.available ? 'configured' : 'not configured'}`).join('; '));
  console.log(`Owners: ${config.owners.length ? config.owners.join(', ') : 'anyone who can log in'}`);
});
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return;
  closing = true;
  await app.close();
  process.exit(0);
});
