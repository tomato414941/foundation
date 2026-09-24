import { createApp } from '../src/app.mjs';
import { FakeAuth, FakeGmail, KEY } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { FakeOpenRouter } from './openrouter-helper.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, githubOauth, gcpOauth } from '../src/adapters.mjs';
import { FakeGitHub } from './github-helper.mjs';
import { FakeGcp } from './gcp-helper.mjs';

// A bucket that lives in memory, so the lent space can be seen and used in the browser tests.
const bucket = new Map();
const space = {
  enabled: true,
  async put(prefix, key, body, contentType) { bucket.set(prefix + key, { body, contentType, updated_at: Date.now() }); },
  async get(prefix, key) {
    const found = bucket.get(prefix + key);
    if (!found) { const error = new Error('not found'); error.status = 404; error.code = 'not_found'; throw error; }
    return { content: found.body, contentType: found.contentType };
  },
  async remove(prefix, key) { bucket.delete(prefix + key); },
  async list(prefix, under) {
    const objects = [...bucket].filter(([name]) => name.startsWith(prefix + under))
      .map(([name, value]) => ({ key: name.slice(prefix.length), size: value.body.length, updated_at: value.updated_at }));
    return { objects, cursor: null };
  },
  async link(prefix, key, seconds) { return 'https://example.test/' + prefix + key + '?expires=' + seconds; },
};

// Test-only providers. Production never imports this module or creates sample accounts.
const auth = new FakeAuth(), gmail = new FakeGmail();
// The browser test can simulate opening a delivered link without any real email.
auth.codeFactory = email => createHash('sha256').update(email).digest('hex');
if (process.env.FOUNDATION_TEST_EMPTY_CONFIG === '1') { auth.enabled = false; gmail.enabled = false; }
const gmailOnly = () => [gmailReadonly(gmail), gmailMetadata(gmail)];
const adapters = process.env.FOUNDATION_TEST_GCP === '1' ? [gcpOauth(new FakeGcp()), ...gmailOnly()]
  : process.env.FOUNDATION_TEST_GITHUB === '1' ? [githubOauth(new FakeGitHub()), ...gmailOnly()]
  : process.env.FOUNDATION_TEST_OPENROUTER === '1' ? [openrouterOauth(new FakeOpenRouter()), ...gmailOnly()]
  : undefined;
const app = createApp({ encryptionKey: KEY, auth, space, adapters: adapters || [gmailReadonly(gmail), gmailMetadata(gmail)] });
const port = Number(process.env.FOUNDATION_TEST_PORT || 3418);
app.server.listen(port, '127.0.0.1', () => console.log('Test fixture: http://127.0.0.1:' + port));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); process.exit(0); });
