import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { GmailClient } from './services/gmail.mjs';
import { OpenRouterClient } from './services/openrouter.mjs';
import { ExpoClient } from './services/expo.mjs';
import { GitHubClient } from './services/github.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, expoLogin, githubOauth } from './adapters.mjs';
import { SupabaseAuth } from './auth.mjs';
import { Kms, resolveEncryptionKey } from './kms.mjs';
import { S3Space } from './objects.mjs';

const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;
const encryptionKey = await resolveEncryptionKey({ database: config.database, encryptionKey: config.encryptionKey, kms });
const auth = new SupabaseAuth(config.supabase);
const gmail = new GmailClient(config.google), expo = new ExpoClient(config.expo);
const github = new GitHubClient(config.github);
const adapters = [githubOauth(github), openrouterOauth(new OpenRouterClient()), ...(config.expo.sessionLogin ? [expoLogin(expo)] : []), gmailReadonly(gmail), gmailMetadata(gmail)];
const app = createApp({ database: config.database, encryptionKey, space: new S3Space(config.objects), publicOrigin: config.publicOrigin, owners: config.owners, trustedProxies: config.trustedProxies, auth, adapters });
app.server.listen(config.port, config.bind, () => {
  console.log(`Foundation: http://${config.bind}:${config.port}`);
  console.log(`Encryption key: ${kms ? 'wrapped by KMS ' + config.kms.keyId : 'plaintext key file or variable'}`);
  if (config.publicOrigin) console.log(`Private preview: ${config.publicOrigin}`);
  console.log(`Supabase Auth: ${auth.enabled ? 'configured' : 'not configured'}; Gmail OAuth: ${gmail.enabled ? 'configured' : 'not configured'}; GitHub OAuth: ${github.enabled ? 'configured' : 'not configured'}`);
  console.log(`Email login: ${auth.emailEnabled ? 'enabled' : 'disabled'}; Object space: ${config.objects.bucket || 'not configured'}`);
  console.log(`Owners: ${config.owners.length ? config.owners.join(', ') : 'anyone who can log in'}`);
});
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return;
  closing = true;
  await app.close();
  process.exit(0);
});
