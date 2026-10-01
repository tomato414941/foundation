import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { builtins } from './catalog.mjs';
import { ResendMailer } from './mailer.mjs';
import { Kms, resolveEncryptionKey } from './kms.mjs';
import { S3Space } from './objects.mjs';
import { FlyRunner } from './runners/fly.mjs';

const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;
const encryptionKey = await resolveEncryptionKey({ database: config.database, encryptionKey: config.encryptionKey, kms });
const mailer = new ResendMailer(config.mail);
const services = builtins();
const runner = config.runner.token && config.runner.app && config.runner.image ? new FlyRunner(config.runner) : null;
const app = createApp({ database: config.database, encryptionKey, runner, space: new S3Space(config.objects), publicOrigin: config.publicOrigin, owners: config.owners, trustedProxies: config.trustedProxies, mailer, services });
app.server.listen(config.port, config.bind, () => {
  console.log(`Foundation: http://${config.bind}:${config.port}`);
  console.log(`Encryption key: ${kms ? 'wrapped by KMS ' + config.kms.keyId : 'plaintext key file or variable'}`);
  if (config.publicOrigin) console.log(`Private preview: ${config.publicOrigin}`);
  console.log(`Email signin: ${mailer.enabled ? 'from ' + config.mail.from : 'disabled'}; Object space: ${config.objects.bucket || 'not configured'}`);
  // Which services Foundation's own side is set up for: its OAuth app, or its role.
  console.log('Services with Foundation\'s own app or role: ' + services.filter(entry => Object.values(entry.schemes).some(scheme => scheme.kind !== 'token' && scheme.available)).map(entry => entry.definition.id).join(', '));
  console.log(`Lent machines: ${runner ? 'Fly Machines, app ' + config.runner.app + ' in ' + config.runner.region : 'not configured'}`);
  console.log(`Owners: ${config.owners.length ? config.owners.join(', ') : 'anyone who can sign in'}`);
});
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return;
  closing = true;
  await app.close();
  process.exit(0);
});
