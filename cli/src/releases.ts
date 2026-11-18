import { createHash } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import { bundleFromJSON } from '@sigstore/bundle';
import { getTrustedRoot } from '@sigstore/tuf';
import { Verifier, toSignedEntity, toTrustMaterial } from '@sigstore/verify';
import type { TrustMaterial } from '@sigstore/verify';
import { secureWrite } from './config.js';

export const packageName = '@tomato414941/foundation';
const registry = 'https://registry.npmjs.org';
// The workflow that publishes the CLI from this repository's main branch, as the certificate Sigstore issues to it
// names it, and the issuer that vouches for that name.
const repository = 'https://github.com/tomato414941/foundation';
const workflowPath = '.github/workflows/publish-cli.yml';
export const releaseWorkflow = repository + '/' + workflowPath + '@refs/heads/main';
const githubActions = 'https://token.actions.githubusercontent.com';
const provenanceType = 'https://slsa.dev/provenance/v1';
const stable = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;
// Checks that a release's provenance came from the release workflow and names the package bytes by this SHA-512 digest.
type ProvenanceCheck = (attestations: unknown, version: string, sha512: string) => Promise<void>;

const Packument = z.object({
  name: z.literal(packageName),
  versions: z.record(z.string(), z.object({ dist: z.object({ tarball: z.string(), integrity: z.string() }) })),
});
const Attestations = z.object({ attestations: z.array(z.object({ predicateType: z.string(), bundle: z.unknown() })) });
const Statement = z.object({
  _type: z.literal('https://in-toto.io/Statement/v1'),
  subject: z.array(z.object({ name: z.string(), digest: z.record(z.string(), z.string()) })),
  predicateType: z.literal(provenanceType),
  predicate: z.object({ buildDefinition: z.object({ externalParameters: z.object({ workflow: z.object({
    repository: z.literal(repository), path: z.literal(workflowPath), ref: z.literal('refs/heads/main'),
  }) }) }) }),
});

export function compareVersions(left: string, right: string) {
  const a = left.split('.').map(Number), b = right.split('.').map(Number);
  for (let index = 0; index < 3; index++) if (a[index] !== b[index]) return a[index]! - b[index]!;
  return 0;
}
function cacheHome() {
  return process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
}
async function read(fetcher: Fetcher, url: string) {
  let response: Response;
  try { response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(60_000) }); }
  catch { throw new Error('Could not reach the npm registry.'); }
  if (!response.ok) throw new Error('The npm registry answered HTTP ' + response.status + ' for ' + url + '.');
  return response;
}

// Accepts the provenance only when Sigstore's certificate authority and transparency log show that the release
// workflow on main signed it, and when it names the package by exactly these bytes.
export function checkProvenance(attestations: unknown, version: string, sha512: string, trust: TrustMaterial) {
  const provenance = Attestations.parse(attestations).attestations.filter(item => item.predicateType === provenanceType);
  if (provenance.length !== 1)
    throw new Error('npm holds no single build provenance for the Foundation CLI ' + version + '.');
  const bundle = bundleFromJSON(provenance[0]!.bundle);
  if (bundle.content.$case !== 'dsseEnvelope') throw new Error('The provenance of ' + version + ' is not a signed statement.');
  try {
    new Verifier(trust).verify(toSignedEntity(bundle), { subjectAlternativeName: releaseWorkflow, extensions: { issuer: githubActions } });
  } catch (error) {
    throw new Error('The provenance of ' + version + ' was not signed by ' + releaseWorkflow + ': ' +
      (error instanceof Error ? error.message : String(error)));
  }
  const envelope = bundle.content.dsseEnvelope;
  if (envelope.payloadType !== 'application/vnd.in-toto+json')
    throw new Error('The provenance of ' + version + ' is not an in-toto statement.');
  const statement = Statement.parse(JSON.parse(envelope.payload.toString('utf8')));
  const name = 'pkg:npm/' + encodeURIComponent('@tomato414941') + '/foundation@' + version;
  if (!statement.subject.some(subject => subject.name === name && subject.digest.sha512 === sha512))
    throw new Error('The provenance of ' + version + ' names other package contents than npm served.');
}
async function checkWithSigstore(attestations: unknown, version: string, sha512: string) {
  const cachePath = join(cacheHome(), 'foundation', 'sigstore');
  await mkdir(cachePath, { recursive: true, mode: 0o700 });
  const root = await getTrustedRoot({ cachePath });
  checkProvenance(attestations, version, sha512, toTrustMaterial(root));
}

// Downloads the newest Foundation CLI release on npm, or the one named, and keeps it in a private file once its
// provenance shows that the release workflow built it. Installing it is left to whoever asked.
export async function downloadRelease(current: string, requested: string | undefined,
  { fetcher = fetch, check = checkWithSigstore, directory = join(cacheHome(), 'foundation', 'releases') }:
  { fetcher?: Fetcher; check?: ProvenanceCheck; directory?: string } = {},
): Promise<{ current: string; newest: string } | { version: string; file: string }> {
  if (requested !== undefined && !stable.test(requested)) throw new Error('Name a release as MAJOR.MINOR.PATCH.');
  const packument = Packument.parse(await (await read(fetcher, registry + '/' + encodeURIComponent(packageName))).json());
  const newest = Object.keys(packument.versions).filter(version => stable.test(version)).sort(compareVersions).at(-1);
  if (!newest) throw new Error('npm lists no release of the Foundation CLI.');
  const version = requested ?? newest;
  if (requested === undefined && compareVersions(version, current) <= 0) return { current, newest };
  const dist = packument.versions[version]?.dist;
  if (!dist) throw new Error('npm lists no Foundation CLI ' + version + '.');
  const tarball = new URL(dist.tarball);
  if (tarball.origin !== registry || !tarball.pathname.startsWith('/' + packageName + '/-/'))
    throw new Error('npm named an unexpected place for the Foundation CLI ' + version + '.');
  const bytes = Buffer.from(await (await read(fetcher, tarball.href)).arrayBuffer());
  const digest = createHash('sha512').update(bytes).digest();
  if ('sha512-' + digest.toString('base64') !== dist.integrity)
    throw new Error('The Foundation CLI ' + version + ' from npm does not match the digest npm lists for it.');
  const attestations: unknown = await (await read(fetcher,
    registry + '/-/npm/v1/attestations/' + encodeURIComponent(packageName) + '@' + version)).json();
  await check(attestations, version, digest.toString('hex'));
  const file = join(directory, 'foundation-' + version + '.tgz');
  await secureWrite(file, bytes, true);
  return { version, file };
}

// Names the CLI release a Foundation server was released with when it is not this one. The number is only shown:
// what to install comes from npm and is checked against the release workflow.
export async function releaseNote(origin: string, current: string, fetcher: Fetcher = fetch) {
  let release: unknown;
  try {
    const response = await fetcher(new URL('/api/release', origin).href, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return null;
    release = await response.json();
  } catch { return null; }
  const parsed = z.object({ cliVersion: z.string().regex(stable) }).safeParse(release);
  if (!parsed.success) return null;
  const server = parsed.data.cliVersion, order = compareVersions(server, current);
  if (order === 0) return null;
  return order > 0
    ? 'This CLI is ' + current + ', and ' + origin + ' was released with CLI ' + server +
      '. Update the CLI: run foundation update, then install the file it names.'
    : 'This CLI is ' + current + ', newer than CLI ' + server + ', which ' + origin + ' was released with.';
}
