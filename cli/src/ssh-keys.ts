import { spawn } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Resource } from '../../shared/contracts.js';
import type { Client } from './client.js';
import { localInputs } from './custody.js';

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
// Runs with an agent of its own holding the private key for a while, so that the key is never written to a file.
export async function withAgent<T>(privateKey: string, use: (socket: string) => Promise<T>) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-agent-'));
  let agent: ReturnType<typeof spawn> | null = null;
  try {
    const socket = join(directory, 'agent.sock');
    let failed = false;
    agent = spawn('ssh-agent', ['-D', '-a', socket], { stdio: 'ignore' });
    agent.once('error', () => { failed = true; });
    for (let attempt = 0; ; attempt++) {
      if (await stat(socket).then(() => true, () => false)) break;
      if (failed || attempt > 250 || agent.exitCode !== null) throw new Error('Install OpenSSH to use a private key kept in Foundation.');
      await delay(20);
    }
    if ((await finish('ssh-add', ['-q', '-t', '900', '-'], { ...process.env, SSH_AUTH_SOCK: socket }, privateKey)).code !== 0)
      throw new Error('The private key could not be loaded into an SSH agent.');
    return await use(socket);
  } finally {
    if (agent && agent.exitCode === null) agent.kill();
    await rm(directory, { recursive: true, force: true });
  }
}

// What an SSH connection gives besides its private key: where it signs in to.
const places = ['SSH_HOST', 'SSH_PORT', 'SSH_USER'];
// Where an SSH connection signs in to, and its private key, opened on this machine with permission to open it.
export async function sshConnection(client: Client, id: string) {
  const connection = await client.json('/api/resources/' + id, {}, Resource);
  if (connection.kind !== 'connection' || !connection.data.outputs.includes('SSH_PRIVATE_KEY'))
    throw new Error('Choose an SSH connection.');
  const names = ['SSH_PRIVATE_KEY', ...places.filter(name => connection.data.outputs.includes(name))];
  const { environment } = await localInputs(client, names.map(name => ({ name, source: { id, output: name }, format: 'text' as const })));
  const { SSH_PRIVATE_KEY: privateKey, ...place } = environment;
  return { privateKey: labeled(privateKey!, connection.name), place };
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
// Runs with the private key of an SSH connection in an agent of its own, and where the connection signs in to.
export async function withConnectionKey<T>(client: Client, id: string, use: (socket: string, place: Record<string, string>) => Promise<T>) {
  const { privateKey, place } = await sshConnection(client, id);
  return withAgent(privateKey, socket => use(socket, place));
}
