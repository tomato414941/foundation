import { createApp } from '../src/app.mjs';
import { FakeAuth, FakeGmail, KEY } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { FakeOpenRouter } from './openrouter-helper.mjs';
import { FakeExpo } from './expo-helper.mjs';
import { FakeExpoLogin } from './expo-login-helper.mjs';
import { gmailConnection, openrouterConnection, expoConnection, apikeyConnection } from '../src/providers/catalog.mjs';
import { ApiKeyProvider } from '../src/providers/apikey.mjs';

// Test-only providers. Production never imports this module or creates sample accounts.
const auth = new FakeAuth(), gmail = new FakeGmail();
// The browser test can simulate opening a delivered link without any real email.
auth.codeFactory = email => createHash('sha256').update(email).digest('hex');
if (process.env.FOUNDATION_TEST_EMPTY_CONFIG === '1') { auth.enabled = false; gmail.enabled = false; }
const integrations = process.env.FOUNDATION_TEST_EXPO_LOGIN === '1' ? [expoConnection(new FakeExpoLogin()), gmailConnection(gmail)] : process.env.FOUNDATION_TEST_EXPO === '1' ? [expoConnection(new FakeExpo()), gmailConnection(gmail)] : process.env.FOUNDATION_TEST_APIKEY === '1' ? [apikeyConnection(new ApiKeyProvider()), gmailConnection(gmail)] : process.env.FOUNDATION_TEST_OPENROUTER === '1' ? [openrouterConnection(new FakeOpenRouter()), gmailConnection(gmail)] : undefined;
const app = createApp({ encryptionKey: KEY, auth, gmail, integrations });
const port = Number(process.env.FOUNDATION_TEST_PORT || 3418);
app.server.listen(port, '127.0.0.1', () => console.log('Test fixture: http://127.0.0.1:' + port));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); process.exit(0); });
