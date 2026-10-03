import test from 'node:test';
import assert from 'node:assert/strict';
import { planRelease, readRegistry, ensureRelease, waitForPublication } from '../.github/scripts/cli-release.mjs';

const pkg = { name: '@tomato414941/foundation', version: '0.20.0', license: 'MIT' };
const registry = (...versions) => ({ name: pkg.name, versions: Object.fromEntries(versions.map(version => [version, { version }])) });
const reply = (body, status = 200) => Response.json(body, { status });
const sha = 'a'.repeat(40), otherSha = 'b'.repeat(40), tag = 'cli-v0.20.0';

test('mainの新しいCLIバージョンを公開対象にする', () => {
  assert.deepEqual(planRelease(pkg, registry('0.18.0', '0.19.0')), { publish: true, tag, reason: '0.20.0 is a new CLI version.' });
});

test('同じCLIバージョンを再び確認すると公開済みとして扱う', () => {
  const plan = planRelease(pkg, registry('0.18.0', '0.20.0'));
  assert.equal(plan.publish, false);
  assert.match(plan.reason, /already published/);
});

test('後続版が公開済みなら古い未公開版より後続版を維持する', () => {
  const plan = planRelease(pkg, registry('0.18.0', '0.21.0'));
  assert.equal(plan.publish, false);
  assert.match(plan.reason, /0\.21\.0/);
});

test('バージョンの各桁を数値として比較して公開を判断する', () => {
  assert.equal(planRelease({ ...pkg, version: '0.10.0' }, registry('0.9.9')).publish, true);
  assert.equal(planRelease({ ...pkg, version: '1.0.0' }, registry('0.99.99')).publish, true);
  assert.equal(planRelease({ ...pkg, version: '0.20.1' }, registry('0.20.0')).publish, true);
  assert.equal(planRelease(pkg, registry('0.20.1')).publish, false);
});

test('正式版の自動公開には公開用のパッケージ名とバージョンとライセンスを求める', () => {
  for (const version of ['0.20', 'v0.20.0', '00.20.0', '0.20.0-beta.1', '0.20.0\nother=value', null]) {
    assert.throws(() => planRelease({ ...pkg, version }, registry('0.18.0')), /stable/);
  }
  assert.throws(() => planRelease({ ...pkg, name: 'another-package' }, registry('0.18.0')), /Unexpected/);
  assert.throws(() => planRelease({ ...pkg, private: true }, registry('0.18.0')), /Unexpected/);
  assert.throws(() => planRelease({ ...pkg, license: 'UNLICENSED' }, registry('0.18.0')), /license/);
});

test('npmのパッケージ情報を確認できた場合に公開を判断する', async () => {
  const metadata = registry('0.18.0');
  const fetched = await readRegistry(async url => {
    assert.equal(new URL(url).hostname, 'registry.npmjs.org');
    assert.equal(decodeURIComponent(new URL(url).pathname.slice(1)), pkg.name);
    return reply(metadata);
  });
  assert.equal(planRelease(pkg, fetched).publish, true);
  for (const body of [{}, { name: pkg.name }, registry(), { name: pkg.name, versions: [] }, { ...metadata, name: 'another-package' }]) {
    assert.throws(() => planRelease(pkg, body), /package versions/);
  }
});

test('npmが404や通信エラーを返した場合は公開の判断を中断する', async () => {
  for (const status of [404, 429, 500]) {
    await assert.rejects(readRegistry(async () => reply({}, status)), new RegExp('HTTP ' + status));
  }
  await assert.rejects(readRegistry(async () => { throw new Error('connection failed'); }), /connection failed/);
  await assert.rejects(readRegistry(async () => new Response('not JSON')), SyntaxError);
});

function githubFixture() {
  const references = new Map(), tags = new Map(), releases = new Map();
  const state = { references, tags, releases, failRelease: false };
  const fetcher = async (url, options = {}) => {
    assert.equal(new URL(url).origin, 'https://api.github.com');
    assert.equal(options.headers.authorization, 'Bearer workflow-token');
    const path = new URL(url).pathname.replace('/repos/owner/foundation', '');
    const method = options.method ?? 'GET', body = options.body && JSON.parse(options.body);
    if (method === 'GET' && path.startsWith('/git/ref/tags/')) {
      const reference = references.get(path.slice('/git/ref/tags/'.length));
      return reference ? reply(reference) : reply({}, 404);
    }
    if (method === 'GET' && path.startsWith('/git/tags/')) return reply(tags.get(path.slice('/git/tags/'.length)));
    if (method === 'POST' && path === '/git/refs') {
      const name = body.ref.slice('refs/tags/'.length);
      if (references.has(name)) return reply({}, 422);
      const reference = { ref: body.ref, object: { type: 'commit', sha: body.sha } };
      references.set(name, reference);
      return reply(reference, 201);
    }
    if (method === 'GET' && path.startsWith('/releases/tags/')) {
      const release = releases.get(path.slice('/releases/tags/'.length));
      return release ? reply(release) : reply({}, 404);
    }
    if (method === 'POST' && path === '/releases') {
      if (state.failRelease) return reply({}, 503);
      if (releases.has(body.tag_name)) return reply({}, 422);
      const release = { id: releases.size + 1, ...body, html_url: 'https://github.com/owner/foundation/releases/tag/' + body.tag_name };
      releases.set(body.tag_name, release);
      return reply(release, 201);
    }
    throw new Error('Unexpected GitHub request: ' + method + ' ' + path);
  };
  return { state, options: { repository: 'owner/foundation', sha, version: pkg.version, token: 'workflow-token', fetcher } };
}

test('テストしたコミットを指すタグと正式なGitHub Releaseを作成する', async () => {
  const { state, options } = githubFixture();
  const url = await ensureRelease(options);
  assert.equal(state.references.get(tag).object.sha, sha);
  const release = state.releases.get(tag);
  assert.equal(release.tag_name, tag);
  assert.equal(release.target_commitish, sha);
  assert.equal(release.draft, false);
  assert.equal(release.prerelease, false);
  assert.equal(url, release.html_url);
});

test('同じコミットの公開処理を再実行すると既存のReleaseを利用する', async () => {
  const { state, options } = githubFixture();
  const url = await ensureRelease(options), id = state.releases.get(tag).id;
  assert.equal(await ensureRelease(options), url);
  assert.equal(state.releases.get(tag).id, id);
  assert.equal(state.references.get(tag).object.sha, sha);
});

test('タグ作成後にRelease作成が失敗しても同じコミットで再開する', async () => {
  const { state, options } = githubFixture();
  state.failRelease = true;
  await assert.rejects(ensureRelease(options), /HTTP 503/);
  assert.equal(state.references.get(tag).object.sha, sha);
  state.failRelease = false;
  assert.equal(await ensureRelease(options), state.releases.get(tag).html_url);
});

test('注釈付きタグがテストしたコミットを指す場合もReleaseを作成する', async () => {
  const { state, options } = githubFixture();
  state.references.set(tag, { object: { type: 'tag', sha: otherSha } });
  state.tags.set(otherSha, { object: { type: 'commit', sha } });
  assert.equal(await ensureRelease(options), state.releases.get(tag).html_url);
  assert.equal(state.tags.get(otherSha).object.sha, sha);
});

test('既存のタグが別のコミットを指す場合は元のタグを保ち不一致を報告する', async () => {
  const { state, options } = githubFixture();
  state.references.set(tag, { object: { type: 'commit', sha: otherSha } });
  await assert.rejects(ensureRelease(options), /another commit/);
  assert.equal(state.references.get(tag).object.sha, otherSha);
});

test('既存の下書きやプレリリースはその状態を保ち確認を求める', async () => {
  for (const kind of ['draft', 'prerelease']) {
    const { state, options } = githubFixture();
    state.references.set(tag, { object: { type: 'commit', sha } });
    state.releases.set(tag, { tag_name: tag, [kind]: true });
    await assert.rejects(ensureRelease(options), /published stable release/);
    assert.equal(state.releases.get(tag)[kind], true);
  }
});

test('GitHubへのアクセスが拒否されたときはその失敗を報告する', async () => {
  const { options } = githubFixture();
  await assert.rejects(ensureRelease({ ...options, fetcher: async () => reply({}, 403) }), /HTTP 403/);
  await assert.rejects(ensureRelease({ ...options, sha: 'main' }), /tested commit/);
});

test('公開した版がnpmのレジストリに反映されてから確認を完了する', async () => {
  let reads = 0;
  await waitForPublication(pkg.version, {
    fetcher: async () => reply(++reads === 1 ? registry('0.18.0') : registry('0.18.0', pkg.version)),
    sleep: async () => {}, attempts: 2,
  });
  assert.equal(reads, 2);
});

test('npmへの反映を確認できない場合は再公開する前の確認を求める', async () => {
  await assert.rejects(waitForPublication(pkg.version, {
    fetcher: async () => reply(registry('0.18.0')), sleep: async () => {}, attempts: 2,
  }), /not visible on npm yet/);
});

test('公開後のnpm確認が一時的に失敗しても反映の確認を続ける', async () => {
  let reads = 0;
  await waitForPublication(pkg.version, {
    fetcher: async () => ++reads === 1 ? reply({}, 503) : reply(registry(pkg.version)),
    sleep: async () => {}, attempts: 2,
  });
  assert.equal(reads, 2);
});

// What is published under a version is fixed: the files of the package as they were when the version was set.
const SHIPPED = { version: '0.23.0', digest: '8349c7f5e6419baaae3abf94f7382220aeb2444cb51ab416983417b857faf756' };
test('CLIのファイルを変えるとバージョンも変える', async () => {
  const { createHash } = await import('node:crypto'), { readFileSync } = await import('node:fs');
  const shipped = JSON.parse(readFileSync(new URL('../cli/package.json', import.meta.url)));
  const hash = createHash('sha256');
  for (const file of shipped.files) hash.update(file + '\0').update(readFileSync(new URL('../cli/' + file, import.meta.url))).update('\0');
  assert.deepEqual({ version: shipped.version, digest: hash.digest('hex') }, SHIPPED, 'The CLI files changed: raise the version in cli/package.json and record it here with the new digest.');
});
