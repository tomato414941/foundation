import { createApp } from '../src/app.mjs';
import { FakeAuth, FakeGmail, KEY } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { FakeOpenRouter } from './openrouter-helper.mjs';
import { FakeExpoLogin } from './expo-login-helper.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, expoLogin, githubOauth } from '../src/adapters.mjs';
import { FakeGitHub } from './github-helper.mjs';

// Test-only providers. Production never imports this module or creates sample accounts.
const auth = new FakeAuth(), gmail = new FakeGmail();
// The browser test can simulate opening a delivered link without any real email.
auth.codeFactory = email => createHash('sha256').update(email).digest('hex');
if (process.env.FOUNDATION_TEST_EMPTY_CONFIG === '1') { auth.enabled = false; gmail.enabled = false; }
const gmailOnly = () => [gmailReadonly(gmail), gmailMetadata(gmail)];
const adapters = process.env.FOUNDATION_TEST_GITHUB === '1' ? [githubOauth(new FakeGitHub()), ...gmailOnly()]
  : process.env.FOUNDATION_TEST_EXPO_LOGIN === '1' ? [expoLogin(new FakeExpoLogin()), ...gmailOnly()]
  : process.env.FOUNDATION_TEST_OPENROUTER === '1' ? [openrouterOauth(new FakeOpenRouter()), ...gmailOnly()]
  : undefined;
const app = createApp({ encryptionKey: KEY, auth, adapters: adapters || [gmailReadonly(gmail), gmailMetadata(gmail)] });
const port = Number(process.env.FOUNDATION_TEST_PORT || 3418);
app.server.listen(port, '127.0.0.1', () => console.log('Test fixture: http://127.0.0.1:' + port));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); process.exit(0); });
