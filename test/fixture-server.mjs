import { createApp } from '../src/app.mjs';
import { LocalRunner } from '../src/runners/local.mjs';
import { FakeMailer, FakeGoogle, KEY } from './helpers.mjs';
import { createHash } from 'node:crypto';
import { FakeOpenRouter } from '../src/adapters/openrouter/fixture.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { openrouterOauth } from '../src/adapters/openrouter/index.mjs';
import { githubOauth } from '../src/adapters/github/index.mjs';
import { FakeGitHub } from '../src/adapters/github/fixture.mjs';
import { ebayOauth } from '../src/adapters/ebay/index.mjs';
import { FakeEbay } from '../src/adapters/ebay/fixture.mjs';
import { cloudflareOauth } from '../src/adapters/cloudflare/index.mjs';
import { FakeCloudflare } from '../src/adapters/cloudflare/fixture.mjs';
import { awsRole } from '../src/adapters/aws/index.mjs';
import { FakeAws } from '../src/adapters/aws/fixture.mjs';
import { FakeOAuth2Service } from '../src/schemes/oauth.fixture.mjs';
import { FakeSlack } from './slack-fixture.mjs';
import { builtins, entry } from '../src/catalog.mjs';

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
const mailer = new FakeMailer(), google = new FakeGoogle();
// The browser test can simulate opening a delivered link without any real email.
const challengeSecret = email => createHash('sha256').update(email).digest('base64url');
if (process.env.FOUNDATION_TEST_EMPTY_CONFIG === '1') { mailer.enabled = false; google.enabled = false; }
const withGoogle = entries => [...entries, entry('google', { oauth: googleOauth(google) })];
// The AWS fixture knows one role, made with the external ID the test reads from the link it is handed.
export const aws = new FakeAws();
aws.lenient = true;
// A service no one knows but its holder, answering plain OAuth 2.0 at service.example.
const described = new FakeOAuth2Service();
const services = process.env.FOUNDATION_TEST_AWS === '1' ? withGoogle([entry('aws', { role: awsRole(aws) })])
  : process.env.FOUNDATION_TEST_CLOUDFLARE === '1' ? withGoogle([entry('cloudflare', { oauth: cloudflareOauth(new FakeCloudflare()) })])
  : process.env.FOUNDATION_TEST_EBAY === '1' ? withGoogle([entry('ebay', { oauth: ebayOauth(new FakeEbay()) })])
  : process.env.FOUNDATION_TEST_GITHUB === '1' ? withGoogle([entry('github', { oauth: githubOauth(new FakeGitHub()) })])
  // Like production today: Foundation has no Slack app of its own, so the holder brings theirs or a token.
  : process.env.FOUNDATION_TEST_SLACK === '1' ? withGoogle([new FakeSlack({ configured: false }).entry()])
  // Every service Foundation knows, none with an app of Foundation's own but Google: what a new deployment shows.
  : process.env.FOUNDATION_TEST_SERVICES === '1' ? [...builtins({}).filter(item => item.definition.id !== 'google'), entry('google', { oauth: googleOauth(google) })]
  : process.env.FOUNDATION_TEST_OPENROUTER === '1' ? withGoogle([entry('openrouter', { oauth: openrouterOauth(new FakeOpenRouter()) })])
  : withGoogle([]);
// Lent machines as directories on this host: enough to see them on the page, isolating nothing.
const app = createApp({ encryptionKey: KEY, mailer, challengeSecret, space, services, serviceFetcher: described.fetch, runner: new LocalRunner(), requestInterval: 0 });
const port = Number(process.env.FOUNDATION_TEST_PORT || 3418);
app.server.listen(port, '127.0.0.1', () => console.log('Test fixture: http://127.0.0.1:' + port));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); process.exit(0); });
