import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { releaseNote } from '../cli/src/releases.js';
import packageInfo from '../cli/package.json' with { type: 'json' };

test('サーバーが別の版の CLI で公開されていれば、その版を示し、上げ方を添える', async () => {
  const answering = (body: unknown, status = 200) => async () => Response.json(body, { status });
  const release = (cliVersion: string) => ({ commit: 'a'.repeat(40), cliVersion, cliSha256: 'b'.repeat(64), verifiedAt: new Date().toISOString() });
  assert.equal(await releaseNote('https://foundation.example', '29.1.0', answering(release('29.2.0'))),
    'This CLI is 29.1.0, and https://foundation.example was released with CLI 29.2.0. ' +
    'Install it: npm install --global --ignore-scripts @tomato414941/foundation@29.2.0');
  assert.equal(await releaseNote('https://foundation.example', '29.1.0', answering(release('29.0.4'))),
    'This CLI is 29.1.0, newer than CLI 29.0.4, which https://foundation.example was released with.');
  assert.equal(await releaseNote('https://foundation.example', '29.1.0', answering(release('29.1.0'))), null);
  assert.equal(await releaseNote('https://foundation.example', '29.1.0',
    answering({ error: { code: 'release_pending', message: 'The release is being verified.' } }, 503)), null);
});

// Runs this CLI's status command against a server that answers its session in a form the CLI does not read.
async function statusAgainst(t: TestContext, cliVersion: string) {
  const server = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(request.url === '/api/release'
      ? { commit: 'a'.repeat(40), cliVersion, cliSha256: 'b'.repeat(64), verifiedAt: new Date().toISOString() }
      : { principal: { id: randomUUID() }, server: { name: 'Foundation', release: 'later' } }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const home = await mkdtemp(join(tmpdir(), 'foundation-cli-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const child = spawn(process.execPath, ['--import', 'tsx', 'cli/src/main.ts', 'status'], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: home, XDG_CACHE_HOME: home,
      FOUNDATION_ORIGIN: 'http://127.0.0.1:' + (server.address() as AddressInfo).port, FOUNDATION_TOKEN: 'a token the test server ignores',
      FOUNDATION_PRINCIPAL_ID: randomUUID() } });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const code = await new Promise(resolve => child.once('close', resolve));
  return { code, stderr, origin: 'http://127.0.0.1:' + (server.address() as AddressInfo).port };
}

test('読めない応答を返したサーバーが別の版の CLI で公開されていれば、両方の版と上げ方を示す', async t => {
  const { code, stderr, origin } = await statusAgainst(t, '999.0.0');
  assert.equal(code, 1);
  assert.equal(stderr, 'foundation: Foundation answered /api/session in a form this CLI does not read.\n' +
    'This CLI is ' + packageInfo.version + ', and ' + origin + ' was released with CLI 999.0.0. ' +
    'Install it: npm install --global --ignore-scripts @tomato414941/foundation@999.0.0\n');
});

test('読めない応答を返したサーバーが同じ版の CLI で公開されていれば、読めなかった中身を示す', async t => {
  const { code, stderr } = await statusAgainst(t, packageInfo.version);
  assert.equal(code, 1);
  assert.match(stderr, /^foundation: Foundation answered \/api\/session in a form this CLI does not read\.\n✖ /);
  assert.doesNotMatch(stderr, /npm install/);
});
