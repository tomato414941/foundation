import { spawn } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { chmod, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { InvalidAuthorizedKeys, NewerAuthorizedKeys, SSHPlan, inspectAuthorizedKeys, withManagedLines } from '../../shared/ssh-access.js';
import type { SSHReport } from '../../shared/ssh-access.js';
import { Resource } from '../../shared/contracts.js';
import { sshKeyText } from '../../shared/ssh.js';
import type { Client } from './client.js';
import { ApiError } from './client.js';
import { localInputs } from './custody.js';

const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
// How the client signs in to the server: a private key file it holds, the key an agent of its own holds with its
// public key in a file, or by default the agent and keys OpenSSH finds for this user. A chosen key is the only one tried.
export interface SSHCredentials { identity?: string; agent?: string }
interface Remote { code: number; stdout: string; stderr: string }
type Failure = Extract<SSHReport, { message?: string }>['outcome'];

async function remote(plan: SSHPlan, account: string, credentials: SSHCredentials, knownHosts: string, script: string) {
  const options = ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'UserKnownHostsFile=' + knownHosts,
    'GlobalKnownHostsFile=/dev/null', 'HostKeyAlias=' + plan.hostId, 'UpdateHostKeys=no', 'CheckHostIP=no',
    'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'ConnectTimeout=10', 'ConnectionAttempts=1',
    'ServerAliveInterval=5', 'ServerAliveCountMax=2', 'ClearAllForwardings=yes', 'ForwardAgent=no', 'ForwardX11=no',
    'PermitLocalCommand=no', 'LogLevel=ERROR',
    ...(credentials.identity ? ['IdentitiesOnly=yes', 'IdentityAgent=' + (credentials.agent ?? 'none')] : [])];
  return new Promise<Remote>((resolve, reject) => {
    const child = spawn('ssh', ['-F', '/dev/null', '-T', '-p', String(plan.port),
      ...(credentials.identity ? ['-i', credentials.identity] : []), ...options.flatMap(option => ['-o', option]),
      '--', account + '@' + plan.address, 'sh -s'], { stdio: ['pipe', 'pipe', 'pipe'] });
    // An authorized keys file is small; a server answering with more than this is stopped and reported as failed.
    let stdout = '', stderr = '', exceeded = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    const limit = () => { exceeded = true; child.kill('SIGKILL'); };
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 8_000_000) limit(); });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 64_000) { stderr = stderr.slice(0, 64_000); limit(); } });
    child.stdin.on('error', () => {});
    child.once('error', () => { clearTimeout(timer); reject(new Error('Install OpenSSH to apply SSH access.')); });
    child.once('close', code => { clearTimeout(timer); resolve(exceeded ? { code: 1, stdout: '', stderr: '' } : { code: code ?? 255, stdout, stderr }); });
    child.stdin.end(script);
  });
}
// Why a connection or a script on the server failed, as the report names it.
function failure(result: Remote): { outcome: Failure; message: string } {
  if (result.code === 255) {
    if (/host key verification failed|remote host identification has changed|no \S+ host key is known/i.test(result.stderr))
      return { outcome: 'host_key_mismatch', message: 'The server did not prove itself with a registered host key.' };
    if (/permission denied/i.test(result.stderr))
      return { outcome: 'denied', message: 'The server did not let this client sign in to the account.' };
    return { outcome: 'unreachable', message: 'The server could not be reached over SSH.' };
  }
  if (result.code === 3) return { outcome: 'conflict', message: 'The authorized keys changed while they were being applied.' };
  if (result.code === 4) return { outcome: 'invalid_file', message: 'The authorized keys file is not a regular file.' };
  return { outcome: 'failed', message: 'The authorized keys could not be read or written on the server.' };
}
// The file, relative to the account's home unless absolute, and the directory that holds it.
const location = (file: string) =>
  'f=' + (file.startsWith('/') ? quote(file) : '"$HOME"/' + quote(file)) + '\nd=$(dirname -- "$f")\n' +
  'if [ -L "$d" ] || [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then exit 4; fi\n';
const readScript = (file: string) => 'set -eu\n' + location(file) +
  'if [ -f "$f" ]; then printf "present\\n"; base64 < "$f"; else printf "absent\\n"; fi\n';
// Replaces the file only if it still holds what was read, under a lock that other clients applying it take as well,
// by renaming a new file over it so that sshd never reads it half written.
const writeScript = (file: string, previous: string | null, next: string) => 'set -eu\numask 077\n' + location(file) + `
if [ ! -d "$d" ]; then mkdir -p -m 700 -- "$d"; fi
lock="$d/.foundation-ssh-access.lock"
if ! mkdir -- "$lock" 2>/dev/null; then
  if [ -n "$(find "$lock" -maxdepth 0 -mmin +2 2>/dev/null)" ] && rmdir -- "$lock" 2>/dev/null && mkdir -- "$lock" 2>/dev/null; then :; else exit 3; fi
fi
old=""; new=""
trap 'rm -f -- "$old" "$new"; rmdir -- "$lock" 2>/dev/null || true' EXIT
if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then exit 4; fi
` + (previous === null ? 'if [ -e "$f" ]; then exit 3; fi\n' : `old=$(mktemp "$d/.foundation-ssh-access.XXXXXX")
printf '%s' ${quote(Buffer.from(previous).toString('base64'))} | base64 -d > "$old"
if ! cmp -s -- "$old" "$f"; then exit 3; fi
`) + `new=$(mktemp "$d/.foundation-ssh-access.XXXXXX")
printf '%s' ${quote(Buffer.from(next).toString('base64'))} | base64 -d > "$new"
chmod 600 -- "$new"
mv -f -- "$new" "$f"
new=""
`;

async function readKeys(run: (script: string) => Promise<Remote>, file: string) {
  const result = await run(readScript(file));
  if (result.code) return failure(result);
  const [state, ...content] = result.stdout.split('\n');
  if (state !== 'present' && state !== 'absent') return { outcome: 'failed' as const, message: 'The server returned an unexpected response.' };
  return { exists: state === 'present', content: Buffer.from(content.join(''), 'base64').toString('utf8') };
}

// Applies the host's plan to one account, or with check only reads it, and says what the account shows afterwards.
async function account(plan: SSHPlan, entry: SSHPlan['accounts'][number], credentials: SSHCredentials, knownHosts: string,
  check: boolean): Promise<SSHReport> {
  const run = (script: string) => remote(plan, entry.account, credentials, knownHosts, script);
  const base = { account: entry.account, generation: entry.generation };
  for (let attempt = 0; attempt < 3; attempt++) {
    const read = await readKeys(run, entry.file);
    if ('outcome' in read) return { ...base, ...read };
    let shown = read.content;
    try {
      const next = check ? read.content : withManagedLines(read.content, plan.hostId, entry.lines, entry.generation);
      if (next !== read.content) {
        const written = await run(writeScript(entry.file, read.exists ? read.content : null, next));
        if (written.code === 3) continue;
        if (written.code) return { ...base, ...failure(written) };
        const again = await readKeys(run, entry.file);
        if ('outcome' in again) return { ...base, ...again };
        shown = again.content;
      }
      return { ...base, outcome: 'verified', ...inspectAuthorizedKeys(shown, plan.hostId) };
    } catch (error) {
      if (error instanceof InvalidAuthorizedKeys) return { ...base, outcome: 'invalid_file', message: error.message };
      if (error instanceof NewerAuthorizedKeys) return { ...base, outcome: 'conflict', message: error.message };
      throw error;
    }
  }
  return { ...base, ...failure({ code: 3, stdout: '', stderr: '' }) };
}

// Applies a plan to the accounts it names, or checks them, and says what each shows, without reporting it.
export async function applyPlan(plan: SSHPlan, credentials: SSHCredentials, check: boolean, accounts?: string[]) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-'));
  try {
    await chmod(directory, 0o700);
    const knownHosts = join(directory, 'known_hosts');
    await writeFile(knownHosts, plan.hostKeys.map(key => plan.hostId + ' ' + key + '\n').join(''), { mode: 0o600 });
    const reports: SSHReport[] = [];
    for (const entry of plan.accounts.filter(entry => !accounts || accounts.includes(entry.account)))
      reports.push(await account(plan, entry, credentials, knownHosts, check));
    return reports;
  } finally { await rm(directory, { recursive: true, force: true }); }
}

// Applies what Foundation decided for each account of the host, or checks it, and reports what each account shows.
// A plan that changed while it was applied is read and applied again once.
export async function applySSHAccess(client: Client, hostId: string, options: { credentials: SSHCredentials; check: boolean; accounts?: string[] }) {
  const results: Array<{ account: string; outcome: string; message?: string }> = [];
  let pending = options.accounts;
  for (let round = 0; round < 2; round++) {
    const plan = await client.json('/api/ssh-hosts/' + hostId + '/plan', {}, SSHPlan);
    if (options.accounts && round === 0)
      for (const name of options.accounts) if (!plan.accounts.some(entry => entry.account === name))
        throw new Error('No key was ever let into account ' + name + ' on this host.');
    const stale: string[] = [];
    for (const report of await applyPlan(plan, options.credentials, options.check, pending)) {
      try {
        await client.json('/api/ssh-hosts/' + hostId + '/reports', { method: 'POST', body: report });
        results.push({ account: report.account, outcome: report.outcome, ...('message' in report && report.message ? { message: report.message } : {}) });
      } catch (error) {
        if (!(error instanceof ApiError) || error.code !== 'ssh_report_stale' || round > 0) throw error;
        stale.push(report.account);
      }
    }
    if (!stale.length) break;
    pending = stale;
  }
  return { hostId, accounts: results };
}

// A new Ed25519 key in OpenSSH's formats, made in memory. Its comment is left empty: the key is named by the label of
// the SSH key it is registered as, which is put on it when it is used.
export function newSSHKey() {
  const seed = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  // PKCS #8 for an Ed25519 key is a fixed prefix followed by its 32-byte seed.
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der', type: 'pkcs8' });
  const raw = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x!, 'base64url');
  const string = (value: Buffer | string) => {
    const bytes = Buffer.from(value), length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    return Buffer.concat([length, bytes]);
  };
  const blob = Buffer.concat([string('ssh-ed25519'), string(raw)]);
  const check = Buffer.from(crypto.getRandomValues(new Uint8Array(4)));
  let section = Buffer.concat([check, check, blob, string(Buffer.concat([seed, raw])), string('')]);
  section = Buffer.concat([section, Buffer.from(Array.from({ length: (8 - section.length % 8) % 8 }, (_, index) => index + 1))]);
  const body = Buffer.concat([Buffer.from('openssh-key-v1\0'), string('none'), string('none'), string(''),
    Buffer.from([0, 0, 0, 1]), string(blob), string(section)]).toString('base64');
  return {
    publicKey: 'ssh-ed25519 ' + blob.toString('base64'),
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\n' + (body.match(/.{1,70}/g) ?? []).join('\n') +
      '\n-----END OPENSSH PRIVATE KEY-----\n',
  };
}

// Runs a program to completion, stopping it after a while, and resolves with its exit code or null when it could not run.
function finish(command: string, args: string[], environment: NodeJS.ProcessEnv, input: string) {
  return new Promise<{ code: number | null; stdout: string }>(resolve => {
    const child = spawn(command, args, { env: environment, stdio: ['pipe', 'pipe', 'ignore'] });
    let stdout = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 64_000) child.kill('SIGKILL'); });
    child.once('error', () => { clearTimeout(timer); resolve({ code: null, stdout: '' }); });
    child.once('close', code => { clearTimeout(timer); resolve({ code: stdout.length > 64_000 ? null : code, stdout }); });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}
// Runs with an agent of its own holding the private key for a while, so that the key is never written to a file. The
// agent must hold exactly the expected public key, which is written next to it for OpenSSH to choose that key alone.
export async function withAgent<T>(privateKey: string, publicKey: string, use: (agent: { socket: string; identity: string }) => Promise<T>) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-agent-'));
  let agent: ReturnType<typeof spawn> | null = null;
  try {
    await chmod(directory, 0o700);
    const socket = join(directory, 'agent.sock'), identity = join(directory, 'identity.pub');
    let failed = false;
    agent = spawn('ssh-agent', ['-D', '-a', socket], { stdio: 'ignore' });
    agent.once('error', () => { failed = true; });
    for (let attempt = 0; ; attempt++) {
      if (await stat(socket).then(() => true, () => false)) break;
      if (failed || attempt > 250 || agent.exitCode !== null) throw new Error('Install OpenSSH to use a private key kept in Foundation.');
      await delay(20);
    }
    const environment = { ...process.env, SSH_AUTH_SOCK: socket };
    if ((await finish('ssh-add', ['-q', '-t', '900', '-'], environment, privateKey)).code !== 0)
      throw new Error('The private key could not be loaded into an SSH agent.');
    const listed = await finish('ssh-add', ['-L'], environment, '');
    const held = listed.code === 0 ? listed.stdout.trim().split('\n').map(line => line.split(/\s+/).slice(0, 2).join(' ')) : [];
    if (held.length !== 1 || held[0] !== sshKeyText(publicKey).publicKey)
      throw new Error('The private key kept in Foundation does not match the public key of this SSH key.');
    await writeFile(identity, held[0] + '\n', { mode: 0o600 });
    return await use({ socket, identity });
  } finally {
    if (agent && agent.exitCode === null) agent.kill();
    await rm(directory, { recursive: true, force: true });
  }
}

// The private key an SSH key keeps in Foundation, opened on this machine with permission to use it, and the public key
// it must match.
export async function storedPrivateKey(client: Client, id: string) {
  const key = await client.json('/api/resources/' + id, {}, Resource);
  if (key.kind !== 'ssh_key' || !key.data.privateKeyId) throw new Error('This SSH key keeps no private key in Foundation.');
  const inputs = await localInputs(client, [{ name: 'SSH_PRIVATE_KEY', source: { id: key.data.privateKeyId }, format: 'text' }]);
  return { privateKey: labeled(inputs.environment.SSH_PRIVATE_KEY!, key.name), publicKey: key.data.publicKey };
}
// The fields each key type keeps in an OpenSSH private key between its type and its comment, as strings or one byte.
const privateFields: Record<string, Array<'string' | 'byte'>> = {
  'ssh-ed25519': ['string', 'string'],
  'ssh-rsa': ['string', 'string', 'string', 'string', 'string', 'string'],
  'ssh-dss': ['string', 'string', 'string', 'string', 'string'],
  'ecdsa-sha2-nistp256': ['string', 'string', 'string'],
  'ecdsa-sha2-nistp384': ['string', 'string', 'string'],
  'ecdsa-sha2-nistp521': ['string', 'string', 'string'],
  'sk-ssh-ed25519@openssh.com': ['string', 'string', 'byte', 'string', 'string'],
  'sk-ecdsa-sha2-nistp256@openssh.com': ['string', 'string', 'string', 'byte', 'string', 'string'],
};
// Reads SSH wire fields one after another, failing with a RangeError past the end.
function reader(bytes: Buffer) {
  let at = 0;
  const take = (length: number) => {
    if (at + length > bytes.length) throw new RangeError('The key is shorter than its fields.');
    at += length;
    return bytes.subarray(at - length, at);
  };
  return { take, string: () => take(take(4).readUInt32BE(0)), get at() { return at; } };
}
const framed = (value: Buffer) => { const length = Buffer.alloc(4); length.writeUInt32BE(value.length); return Buffer.concat([length, value]); };
// An unencrypted OpenSSH private key with its comment replaced in memory, so that an agent lists it by the name given.
// The key kept in Foundation is not changed; a key in another format, or of a type not known here, is returned as it is.
export function labeled(privateKey: string, comment: string) {
  const armor = /^-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END OPENSSH PRIVATE KEY-----$/.exec(privateKey.trim());
  if (!armor) return privateKey;
  try {
    const outer = reader(Buffer.from(armor[1]!.replace(/\n/g, ''), 'base64'));
    if (outer.take(15).toString('latin1') !== 'openssh-key-v1\0') return privateKey;
    const cipher = outer.string(), kdf = outer.string(), kdfOptions = outer.string(), count = outer.take(4);
    if (cipher.toString() !== 'none' || count.readUInt32BE(0) !== 1) return privateKey;
    const publicBlob = outer.string(), section = outer.string();
    const inner = reader(section);
    inner.take(8);
    const layout = privateFields[inner.string().toString()];
    if (!layout) return privateKey;
    for (const field of layout) if (field === 'byte') inner.take(1); else inner.string();
    let next = Buffer.concat([section.subarray(0, inner.at), framed(Buffer.from(comment))]);
    next = Buffer.concat([next, Buffer.from(Array.from({ length: (8 - next.length % 8) % 8 }, (_, index) => index + 1))]);
    const body = Buffer.concat([Buffer.from('openssh-key-v1\0', 'latin1'), framed(cipher), framed(kdf), framed(kdfOptions), count,
      framed(publicBlob), framed(next)]).toString('base64');
    return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + (body.match(/.{1,70}/g) ?? []).join('\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
  } catch (error) {
    if (error instanceof RangeError) return privateKey;
    throw error;
  }
}
// Runs with the private key an SSH key keeps in Foundation in an agent of its own.
export async function withStoredKey<T>(client: Client, id: string, use: (agent: { socket: string; identity: string }) => Promise<T>) {
  const { privateKey, publicKey } = await storedPrivateKey(client, id);
  return withAgent(privateKey, publicKey, use);
}
// Applies or checks a host's authorized keys, signing in with a private key file, a key kept in Foundation, or by
// default the agent and keys OpenSSH finds for this user.
export async function sshAccess(client: Client, hostId: string,
  options: { check: boolean; account?: string; identity?: string; keyId?: string }) {
  if (options.identity && options.keyId) throw new Error('Choose a private key file or an SSH key kept in Foundation.');
  const run = (credentials: SSHCredentials) => applySSHAccess(client, hostId, { credentials, check: options.check,
    ...(options.account ? { accounts: [options.account] } : {}) });
  if (options.keyId) return withStoredKey(client, options.keyId, agent => run({ agent: agent.socket, identity: agent.identity }));
  return run(options.identity ? { identity: options.identity } : {});
}
