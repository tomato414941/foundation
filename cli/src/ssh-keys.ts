import { spawn } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { chmod, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Resource } from '../../shared/contracts.js';
import { sshKeyText } from '../../shared/ssh.js';
import type { Client } from './client.js';
import { localInputs } from './custody.js';

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
