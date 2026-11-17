import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { checkPublishedContent } from '../.github/scripts/cli-release.mjs';
import { verifiedRelease } from '../server/release.js';

test('切り替え中は検証待ちを返し、現在のリリースの検証が完了したら公開する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-release-state-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const previous = process.env.FOUNDATION_RELEASE_COMMIT;
  t.after(() => {
    if (previous === undefined) delete process.env.FOUNDATION_RELEASE_COMMIT;
    else process.env.FOUNDATION_RELEASE_COMMIT = previous;
  });
  process.env.FOUNDATION_RELEASE_COMMIT = 'a'.repeat(40);
  const manifest = { commit: 'a'.repeat(40), cliVersion: '18.0.0', cliSha256: 'b'.repeat(64),
    verifiedAt: '2026-10-14T20:00:00Z' };
  await writeFile(join(directory, 'release.json'), JSON.stringify({ commit: 'd'.repeat(40), cliVersion: '17.0.0' }));
  assert.equal(await verifiedRelease(directory), null);
  await writeFile(join(directory, 'release.json'), JSON.stringify(manifest));
  assert.deepEqual(await verifiedRelease(directory), manifest);
});

test('公開済みCLIと同じ内容を許可し、配布内容の変更にはバージョン変更を要求する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-package-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(join(directory, 'package/dist'), { recursive: true });
  await writeFile(join(directory, 'package/dist/cli.mjs'), 'original-cli');
  const packed = execFileSync('tar', ['-czf', '-', '-C', directory, 'package']);
  const pkg = { version: '5.1.0' };
  const registry = { versions: { '5.1.0': { dist: { tarball: 'https://registry.npmjs.org/package.tgz',
    integrity: 'sha512-' + createHash('sha512').update(packed).digest('base64') } } } };
  const fetcher = async () => new Response(packed);
  const artifacts = { 'dist/cli.mjs': Buffer.from('original-cli') };
  await checkPublishedContent(pkg, registry, artifacts, fetcher);
  await assert.rejects(checkPublishedContent(pkg, registry, { ...artifacts, 'dist/cli.mjs': Buffer.from('updated-cli') }, fetcher), /Increase/);
});

