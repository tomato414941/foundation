import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
// Each case loads the real browser module in an isolated DOM/process: no module
// cache, globals, credentials, timers, or locale can leak to another test.
for (const mode of ['account-settings-ja', 'account-settings-en', 'boot', 'deny', 'transfer', 'account-transfer', 'editing', 'signin', 'confirm', 'passkey-signin', 'passkey-signup', 'passkey-local']) {
  test(`Web locale placement and state guards during ${mode}`, async () => {
    await run(process.execPath, [fileURLToPath(new URL('./web-i18n-client.fixture.mjs', import.meta.url)), mode], { timeout: 15_000 });
  });
}
