import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { GmailProvider } from './providers/gmail.mjs';
import { OpenRouterProvider } from './providers/openrouter.mjs';
import { ExpoProvider } from './providers/expo.mjs';
import { gmailConnection, openrouterConnection, expoConnection, apikeyConnection, supabaseConnection, cloudflareConnection, appleConnection, awsConnection } from './providers/catalog.mjs';
import { ApiKeyProvider } from './providers/apikey.mjs';
import { SupabaseProvider } from './providers/supabase.mjs';
import { AppleProvider } from './providers/apple.mjs';
import { AwsProvider } from './providers/aws.mjs';
import { CloudflareProvider } from './providers/cloudflare.mjs';
import { SupabaseAuth } from './auth.mjs';
import { Kms, resolveEncryptionKey } from './kms.mjs';

const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;
const encryptionKey = await resolveEncryptionKey({ database: config.database, encryptionKey: config.encryptionKey, kms });
const auth = new SupabaseAuth(config.supabase);
const gmail = new GmailProvider(config.google);
const openrouter = new OpenRouterProvider();
const app = createApp({ database: config.database, encryptionKey, publicOrigin: config.publicOrigin, trustedProxies: config.trustedProxies, auth, gmail, integrations: [openrouterConnection(openrouter), expoConnection(new ExpoProvider(config.expo)), supabaseConnection(new SupabaseProvider()), cloudflareConnection(new CloudflareProvider()), appleConnection(new AppleProvider()), awsConnection(new AwsProvider(), config.aws), gmailConnection(gmail), apikeyConnection(new ApiKeyProvider())] });
app.server.listen(config.port, config.bind, () => {
  console.log(`Foundation: http://${config.bind}:${config.port}`);
  console.log(`Encryption key: ${kms ? 'wrapped by KMS ' + config.kms.keyId : 'plaintext key file or variable'}`);
  if (config.publicOrigin) console.log(`Private preview: ${config.publicOrigin}`);
  console.log(`Supabase Auth: ${auth.enabled ? 'configured' : 'not configured'}; Gmail OAuth: ${gmail.enabled ? 'configured' : 'not configured'}`);
  console.log(`Email login: ${auth.emailEnabled ? 'enabled' : 'disabled'}`);
});
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return;
  closing = true;
  await app.close();
  process.exit(0);
});
