import { configuration } from './config.mjs';
import { createApp } from './app.mjs';
import { GmailProvider } from './providers/gmail.mjs';
import { OpenRouterProvider } from './providers/openrouter.mjs';
import { ExpoProvider } from './providers/expo.mjs';
import { gmailConnection, openrouterConnection, expoConnection, apikeyConnection } from './providers/catalog.mjs';
import { ApiKeyProvider } from './providers/apikey.mjs';
import { SupabaseAuth } from './auth.mjs';

const config = configuration();
const auth = new SupabaseAuth(config.supabase);
const gmail = new GmailProvider(config.google);
const openrouter = new OpenRouterProvider();
const app = createApp({ database: config.database, encryptionKey: config.encryptionKey, publicOrigin: config.publicOrigin, auth, gmail, integrations: [openrouterConnection(openrouter), expoConnection(new ExpoProvider(config.expo)), gmailConnection(gmail), apikeyConnection(new ApiKeyProvider())] });
app.server.listen(config.port, '127.0.0.1', () => {
  console.log(`Foundation: http://127.0.0.1:${config.port}`);
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
