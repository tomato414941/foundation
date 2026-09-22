import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { GmailClient } from './services/gmail.mjs';
import { OpenRouterClient } from './services/openrouter.mjs';
import { ExpoClient } from './services/expo.mjs';
import { SupabaseClient } from './services/supabase.mjs';
import { AppleClient } from './services/apple.mjs';
import { AwsClient } from './services/aws.mjs';
import { CloudflareClient } from './services/cloudflare.mjs';
import { GenericClient } from './generic.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, expoToken, expoLogin, supabaseAccessToken, cloudflareApiToken, appleApiKey, awsIamUserKey, generic } from './adapters.mjs';
import { SupabaseAuth } from './auth.mjs';
import { Kms, resolveEncryptionKey } from './kms.mjs';

const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;
const encryptionKey = await resolveEncryptionKey({ database: config.database, encryptionKey: config.encryptionKey, kms });
const auth = new SupabaseAuth(config.supabase);
const gmail = new GmailClient(config.google), expo = new ExpoClient(config.expo);
const adapters = [openrouterOauth(new OpenRouterClient()), expoToken(expo), ...(config.expo.sessionLogin ? [expoLogin(expo)] : []), supabaseAccessToken(new SupabaseClient()), cloudflareApiToken(new CloudflareClient()), appleApiKey(new AppleClient()), awsIamUserKey(new AwsClient(), config.aws), gmailReadonly(gmail), gmailMetadata(gmail), generic(new GenericClient())];
const app = createApp({ database: config.database, encryptionKey, publicOrigin: config.publicOrigin, trustedProxies: config.trustedProxies, auth, adapters });
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
