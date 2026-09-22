import { createApp } from '../src/app.mjs';
import { FakeAuth, FakeGmail, KEY } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { FakeOpenRouter } from './openrouter-helper.mjs';
import { FakeExpo } from './expo-helper.mjs';
import { FakeExpoLogin } from './expo-login-helper.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, expoToken, expoLogin, generic, supabaseAccessToken, cloudflareApiToken, appleApiKey, awsIamUserKey } from '../src/adapters.mjs';
import { GenericClient } from '../src/generic.mjs';
import { FakeSupabase } from './supabase-helper.mjs';
import { FakeApple } from './apple-helper.mjs';
import { FakeAws } from './aws-helper.mjs';
import { FakeCloudflare } from './cloudflare-helper.mjs';

// Test-only providers. Production never imports this module or creates sample accounts.
const auth = new FakeAuth(), gmail = new FakeGmail();
// The browser test can simulate opening a delivered link without any real email.
auth.codeFactory = email => createHash('sha256').update(email).digest('hex');
if (process.env.FOUNDATION_TEST_EMPTY_CONFIG === '1') { auth.enabled = false; gmail.enabled = false; }
const adapters = process.env.FOUNDATION_TEST_CLOUDFLARE === '1' ? [cloudflareApiToken(new FakeCloudflare()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_EXPO_LOGIN === '1' ? [expoLogin(new FakeExpoLogin()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_EXPO === '1' ? [expoToken(new FakeExpo()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_APIKEY === '1' ? [generic(new GenericClient()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_AWS === '1' ? [awsIamUserKey(new FakeAws()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_APPLE === '1' ? [appleApiKey(new FakeApple()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_SUPABASE === '1' ? [supabaseAccessToken(new FakeSupabase()), gmailReadonly(gmail), gmailMetadata(gmail)] : process.env.FOUNDATION_TEST_OPENROUTER === '1' ? [openrouterOauth(new FakeOpenRouter()), gmailReadonly(gmail), gmailMetadata(gmail)] : undefined;
const app = createApp({ encryptionKey: KEY, auth, adapters: adapters || [gmailReadonly(gmail), gmailMetadata(gmail)] });
const port = Number(process.env.FOUNDATION_TEST_PORT || 3418);
app.server.listen(port, '127.0.0.1', () => console.log('Test fixture: http://127.0.0.1:' + port));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); process.exit(0); });
