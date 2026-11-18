import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { TrustedRoot } from '@sigstore/protobuf-specs';
import { toTrustMaterial } from '@sigstore/verify';
import { checkProvenance, downloadRelease, packageName, releaseNote } from '../cli/src/releases.js';
import packageInfo from '../cli/package.json' with { type: 'json' };

const fixture = async (name: string) =>
  JSON.parse(await readFile(new URL('./fixtures/' + name, import.meta.url), 'utf8')) as unknown;
const trust = async () => toTrustMaterial(TrustedRoot.fromJSON(await fixture('sigstore-trusted-root.json')));
// What npm served as the Foundation CLI 29.0.4, which the release workflow on main built, named by its SHA-512 digest.
const published = { version: '29.0.4',
  sha512: '2d0ce36627d1f304d03682c109e80894b5446ba4291cceaaa07008eb46bbb1f18adfeada16469529eee616a34069822a3b9b8cc4e9433a412ee658262adc99ea' };
type Attestations = { attestations: Array<{ predicateType: string; bundle: { dsseEnvelope?: { payload: string } } }> };

test('このリポジトリの main の公開ワークフローが署名し、受け取った中身を名指す provenance を受け入れる', async () => {
  checkProvenance(await fixture('npm-attestations-foundation-29.0.4.json'), published.version, published.sha512, await trust());
});

test('別のリポジトリのワークフローが署名した provenance は受け入れない', async () => {
  const other = await fixture('npm-attestations-sigstore-verify-4.1.2.json'), material = await trust();
  assert.throws(() => checkProvenance(other, '4.1.2', published.sha512, material),
    /was not signed by https:\/\/github\.com\/tomato414941\/foundation\/\.github\/workflows\/publish-cli\.yml@refs\/heads\/main/);
});

test('provenance が名指す中身と npm から受け取った中身が違えば受け入れない', async () => {
  const attestations = await fixture('npm-attestations-foundation-29.0.4.json'), material = await trust();
  assert.throws(() => checkProvenance(attestations, published.version, createHash('sha512').update('other').digest('hex'), material),
    /names other package contents/);
  assert.throws(() => checkProvenance(attestations, '29.0.5', published.sha512, material), /names other package contents/);
});

test('書き換えた provenance は受け入れない', async () => {
  const attestations = await fixture('npm-attestations-foundation-29.0.4.json') as Attestations;
  const provenance = attestations.attestations.find(item => item.predicateType === 'https://slsa.dev/provenance/v1')!;
  const statement = JSON.parse(Buffer.from(provenance.bundle.dsseEnvelope!.payload, 'base64').toString('utf8'));
  statement.subject[0].digest.sha512 = createHash('sha512').update('other').digest('hex');
  provenance.bundle.dsseEnvelope!.payload = Buffer.from(JSON.stringify(statement)).toString('base64');
  const material = await trust();
  assert.throws(() => checkProvenance(attestations, published.version, statement.subject[0].digest.sha512, material), /was not signed by/);
});

test('ビルドの provenance がない版は受け入れない', async () => {
  const attestations = await fixture('npm-attestations-foundation-29.0.4.json') as Attestations;
  attestations.attestations = attestations.attestations.filter(item => item.predicateType !== 'https://slsa.dev/provenance/v1');
  const material = await trust();
  assert.throws(() => checkProvenance(attestations, published.version, published.sha512, material), /no single build provenance/);
});

// A registry holding the releases given, which answers the attestation request with a marker the check receives.
function registry(releases: Record<string, Buffer>, tarball = (version: string) =>
  'https://registry.npmjs.org/' + packageName + '/-/foundation-' + version + '.tgz') {
  const requests: string[] = [];
  const integrity = (bytes: Buffer) => 'sha512-' + createHash('sha512').update(bytes).digest('base64');
  const fetcher = async (url: string) => {
    requests.push(url);
    if (url === 'https://registry.npmjs.org/' + encodeURIComponent(packageName))
      return Response.json({ name: packageName, versions: Object.fromEntries(Object.entries(releases).map(([version, bytes]) =>
        [version, { dist: { tarball: tarball(version), integrity: integrity(bytes) } }])) });
    const release = Object.entries(releases).find(([version]) => url === tarball(version));
    if (release) return new Response(new Uint8Array(release[1]));
    const attested = url.match(/^https:\/\/registry\.npmjs\.org\/-\/npm\/v1\/attestations\/%40tomato414941%2Ffoundation@(.+)$/);
    if (attested) return Response.json({ attestations: [], version: attested[1] });
    return new Response('missing', { status: 404 });
  };
  return { fetcher, requests };
}
async function directory(t: TestContext) {
  const path = await mkdtemp(join(tmpdir(), 'foundation-releases-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return join(path, 'releases');
}

test('npm の一番新しい版を取り、npm の示すダイジェストと provenance を確かめてから、本人だけが読めるファイルに置く', async t => {
  const releases = { '29.0.9': Buffer.from('older release'), '29.10.0': Buffer.from('newest release'), '29.2.0': Buffer.from('middle') };
  const { fetcher } = registry(releases), place = await directory(t), checked: unknown[] = [];
  const result = await downloadRelease('29.1.0', undefined, { fetcher, directory: place,
    check: async (attestations, version, sha512) => { checked.push({ attestations, version, sha512 }); } });
  assert.deepEqual(result, { version: '29.10.0', file: join(place, 'foundation-29.10.0.tgz') });
  assert.deepEqual(checked, [{ attestations: { attestations: [], version: '29.10.0' }, version: '29.10.0',
    sha512: createHash('sha512').update(releases['29.10.0']).digest('hex') }]);
  assert.deepEqual(await readFile(join(place, 'foundation-29.10.0.tgz')), releases['29.10.0']);
  assert.equal((await stat(join(place, 'foundation-29.10.0.tgz'))).mode & 0o777, 0o600);
});

test('名指した版は、いまより古くても同じ確かめ方を経て置く', async t => {
  const { fetcher } = registry({ '29.0.9': Buffer.from('older release'), '29.10.0': Buffer.from('newest release') });
  const place = await directory(t), checked: string[] = [];
  const result = await downloadRelease('29.1.0', '29.0.9', { fetcher, directory: place,
    check: async (_attestations, version) => { checked.push(version); } });
  assert.deepEqual(result, { version: '29.0.9', file: join(place, 'foundation-29.0.9.tgz') });
  assert.deepEqual(checked, ['29.0.9']);
});

test('いまの版が一番新しければ、配布物を取らない', async t => {
  const { fetcher, requests } = registry({ '29.0.9': Buffer.from('older release'), '29.1.0': Buffer.from('this release') });
  const result = await downloadRelease('29.1.0', undefined, { fetcher, directory: await directory(t),
    check: async () => { throw new Error('Not checked.'); } });
  assert.deepEqual(result, { current: '29.1.0', newest: '29.1.0' });
  assert.deepEqual(requests, ['https://registry.npmjs.org/' + encodeURIComponent(packageName)]);
});

test('npm の示すダイジェストと違う中身や、provenance を確かめられない版や、npm の外を指す配布物は置かない', async t => {
  const place = await directory(t), accept = async () => {};
  const changed = registry({ '29.2.0': Buffer.from('newest release') });
  const served = changed.fetcher;
  const fetcher = async (url: string) => url.endsWith('.tgz') ? new Response('changed on the way') : served(url);
  await assert.rejects(downloadRelease('29.1.0', undefined, { fetcher, directory: place, check: accept }),
    /does not match the digest npm lists/);
  await assert.rejects(downloadRelease('29.1.0', undefined, { fetcher: registry({ '29.2.0': Buffer.from('newest release') }).fetcher,
    directory: place, check: async () => { throw new Error('The provenance was not signed by the release workflow.'); } }),
  /not signed by the release workflow/);
  await assert.rejects(downloadRelease('29.1.0', undefined, { fetcher: registry({ '29.2.0': Buffer.from('newest release') },
    version => 'https://example.com/foundation-' + version + '.tgz').fetcher, directory: place, check: accept }),
  /unexpected place/);
  await assert.rejects(readdir(place), { code: 'ENOENT' });
});

test('npm が想定外の形で答えたときは、そう示す', async t => {
  const place = await directory(t);
  await assert.rejects(downloadRelease('29.1.0', undefined, { fetcher: async () => Response.json({ name: packageName }), directory: place }),
    /npm described the Foundation CLI in an unexpected form/);
  const material = await trust();
  assert.throws(() => checkProvenance({ attestation: [] }, '29.1.0', published.sha512, material),
    /npm listed the attestations of the Foundation CLI 29\.1\.0 in an unexpected form/);
});

test('サーバーが別の版の CLI で公開されていれば、その版を示し、上げ方を添える', async () => {
  const answering = (body: unknown, status = 200) => async () => Response.json(body, { status });
  const release = (cliVersion: string) => ({ commit: 'a'.repeat(40), cliVersion, cliSha256: 'b'.repeat(64), verifiedAt: new Date().toISOString() });
  assert.equal(await releaseNote('https://foundation.example', '29.1.0', answering(release('29.2.0'))),
    'This CLI is 29.1.0, and https://foundation.example was released with CLI 29.2.0. Update the CLI: run foundation update, then install the file it names.');
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
    'Update the CLI: run foundation update, then install the file it names.\n');
});

test('読めない応答を返したサーバーが同じ版の CLI で公開されていれば、読めなかった中身を示す', async t => {
  const { code, stderr } = await statusAgainst(t, packageInfo.version);
  assert.equal(code, 1);
  assert.match(stderr, /^foundation: Foundation answered \/api\/session in a form this CLI does not read\.\n✖ /);
  assert.doesNotMatch(stderr, /foundation update/);
});
