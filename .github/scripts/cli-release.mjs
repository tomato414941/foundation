import { appendFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const packageName = '@tomato414941/foundation';
const stableVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function parts(version) {
  if (typeof version !== 'string' || !stableVersion.test(version))
    throw new Error('The CLI version must be a stable major.minor.patch version.');
  const numbers = version.split('.').map(Number);
  if (!numbers.every(Number.isSafeInteger)) throw new Error('The CLI version is too large.');
  return numbers;
}

export function planRelease(pkg, registry) {
  if (pkg.name !== packageName || pkg.private === true) throw new Error('Unexpected CLI package.');
  if (!pkg.license || pkg.license === 'UNLICENSED')
    throw new Error('Choose the CLI license before publishing.');
  const candidate = parts(pkg.version),
    tag = 'cli-v' + pkg.version;
  if (
    registry?.name !== packageName ||
    !registry.versions ||
    typeof registry.versions !== 'object' ||
    Array.isArray(registry.versions) ||
    !Object.keys(registry.versions).length
  ) {
    throw new Error('npm did not return the package versions.');
  }
  if (Object.hasOwn(registry.versions, pkg.version))
    return { publish: false, tag, reason: pkg.version + ' is already published.' };
  for (const version of Object.keys(registry.versions).filter((version) => stableVersion.test(version))) {
    const published = parts(version);
    const different = candidate.findIndex((value, index) => value !== published[index]);
    if (different >= 0 && candidate[different] < published[different]) {
      return { publish: false, tag, reason: version + ' is already published; keeping the newer version.' };
    }
  }
  return { publish: true, tag, reason: pkg.version + ' is a new CLI version.' };
}

export async function readRegistry(fetcher = fetch) {
  const response = await fetcher('https://registry.npmjs.org/' + encodeURIComponent(packageName), {
    headers: { 'cache-control': 'no-cache' },
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  // A failure to read this existing package is not evidence of an unpublished version.
  if (!response.ok)
    throw new Error('Cannot check published CLI versions (npm HTTP ' + response.status + ').');
  return response.json();
}

export async function checkPublishedContent(pkg, registry, artifacts, fetcher = fetch) {
  const published = registry.versions[pkg.version];
  if (!published) return;
  const url = new URL(published.dist.tarball);
  if (url.origin !== 'https://registry.npmjs.org') throw new Error('Unexpected npm package origin.');
  const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error('Could not read the published CLI.');
  const packed = Buffer.from(await response.arrayBuffer());
  const integrity = 'sha512-' + createHash('sha512').update(packed).digest('base64');
  if (integrity !== published.dist.integrity) throw new Error('The published package failed its integrity check.');
  for (const [name, bytes] of Object.entries(artifacts)) {
    const previous = execFileSync('tar', ['-xzOf', '-', 'package/' + name], { input: packed, maxBuffer: 40_000_000 });
    if (!Buffer.from(bytes).equals(previous))
      throw new Error('The CLI distribution changed. Increase cli/package.json version before releasing.');
  }
}

export async function ensureRelease({ repository, sha, version, token, fetcher = fetch }) {
  parts(version);
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '') ||
    !/^[a-f0-9]{40}$/.test(sha ?? '') ||
    !token
  ) {
    throw new Error('The GitHub repository, tested commit and workflow token are required.');
  }
  const tag = 'cli-v' + version,
    base = 'https://api.github.com/repos/' + repository;
  async function request(path, { method = 'GET', body, missing = false } = {}) {
    const response = await fetcher(base + path, {
      method,
      headers: {
        authorization: 'Bearer ' + token,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'x-github-api-version': '2026-03-10',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
    if (missing && response.status === 404) return null;
    if (!response.ok)
      throw new Error('GitHub ' + method + ' ' + path + ' returned HTTP ' + response.status + '.');
    return response.json();
  }
  let reference = await request('/git/ref/tags/' + tag, { missing: true });
  if (!reference) {
    reference = await request('/git/refs', { method: 'POST', body: { ref: 'refs/tags/' + tag, sha } });
  }
  let object = reference.object;
  for (let depth = 0; object?.type === 'tag' && depth < 10; depth++) {
    object = (await request('/git/tags/' + object.sha)).object;
  }
  if (object?.type !== 'commit' || object.sha !== sha) {
    throw new Error(
      tag + ' points to another commit. Rerun the original release workflow or choose a new CLI version.',
    );
  }
  let release = await request('/releases/tags/' + tag, { missing: true });
  if (!release) {
    release = await request('/releases', {
      method: 'POST',
      body: {
        tag_name: tag,
        target_commitish: sha,
        name: 'Foundation CLI ' + version,
        body: 'Foundation CLI ' + version,
        draft: false,
        prerelease: false,
        make_latest: 'true',
      },
    });
  }
  if (release.tag_name !== tag || release.draft || release.prerelease) {
    throw new Error('The existing GitHub Release must be a published stable release for ' + tag + '.');
  }
  return release.html_url;
}

// npm can take many minutes to show a version it accepted, so this waits up to half an hour.
export async function waitForPublication(version, { fetcher = fetch, sleep = delay, attempts = 120 } = {}) {
  parts(version);
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const registry = await readRegistry(fetcher);
      if (
        registry?.name !== packageName ||
        !registry.versions ||
        typeof registry.versions !== 'object' ||
        Array.isArray(registry.versions)
      ) {
        throw new Error('npm did not return the package versions.');
      }
      if (Object.hasOwn(registry.versions, version)) return;
      lastError = null;
    } catch (error) {
      lastError = error;
    }
    if (attempt < attempts) await sleep(15_000);
  }
  throw new Error(version + ' is not visible on npm yet. Check the registry before retrying publication.', {
    cause: lastError,
  });
}

async function main() {
  const pkg = JSON.parse(readFileSync('cli/package.json', 'utf8'));
  switch (process.argv[2]) {
    case 'plan': {
      if (!readFileSync('cli/LICENSE', 'utf8').trim()) throw new Error('The CLI license text is required.');
      if (process.env.RELEASE_TAG && process.env.RELEASE_TAG !== 'cli-v' + pkg.version)
        throw new Error('The release tag must match the CLI package version.');
      const registry = await readRegistry();
      await checkPublishedContent(pkg, registry, { 'dist/cli.mjs': readFileSync('cli/dist/cli.mjs'), 'dist/agent.mjs': readFileSync('cli/dist/agent.mjs') });
      const plan = planRelease(pkg, registry);
      appendFileSync(process.env.GITHUB_OUTPUT, 'publish=' + plan.publish + '\ntag=' + plan.tag + '\n');
      console.log(plan.reason);
      break;
    }
    case 'github': {
      let sha = process.env.GITHUB_SHA;
      try {
        const tag = 'cli-v' + pkg.version;
        const source = execFileSync('git', ['rev-parse', 'refs/tags/' + tag + '^{commit}'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        execFileSync('git', ['merge-base', '--is-ancestor', source, sha], { stdio: 'ignore' });
        const tagged = JSON.parse(execFileSync('git', ['show', tag + ':cli/package.json'], { encoding: 'utf8' }));
        if (tagged.version !== pkg.version) throw new Error('The existing CLI tag has another version.');
        sha = source;
      } catch (error) {
        if (error.status !== 128) throw error;
      }
      console.log(
        await ensureRelease({
          repository: process.env.GITHUB_REPOSITORY,
          sha,
          version: pkg.version,
          token: process.env.GH_TOKEN,
        }),
      );
      break;
    }
    case 'wait':
      await waitForPublication(pkg.version);
      console.log('npm has published ' + packageName + '@' + pkg.version + '.');
      break;
    case 'verify': {
      const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
      url.searchParams.set('audience', 'npm:registry.npmjs.org');
      const identity = await fetch(url, { headers: { Authorization: 'Bearer ' + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN },
        signal: AbortSignal.timeout(30_000), redirect: 'error' });
      if (!identity.ok) throw new Error('GitHub OIDC returned HTTP ' + identity.status);
      const { value } = await identity.json();
      if (!value) throw new Error('GitHub did not return an OIDC token.');
      const exchange = await fetch('https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/' + encodeURIComponent(packageName), {
        method: 'POST', headers: { Authorization: 'Bearer ' + value }, signal: AbortSignal.timeout(30_000), redirect: 'error',
      });
      if (!exchange.ok) throw new Error('npm rejected the trusted publisher (HTTP ' + exchange.status + ').');
      if (!(await exchange.json()).token) throw new Error('npm did not issue a publication token.');
      console.log('npm accepted this workflow. No package was published.');
      break;
    }
    default:
      throw new Error('Usage: cli-release.mjs <plan|github|wait|verify>');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
