import { createHash } from 'node:crypto';
import { z } from 'zod';
import { Id } from './contracts.js';
import { AuthorizedKeysFile, SSHAccount, SSHAddress, SSHFingerprint, SSHPublicKey, sshKeyText } from './ssh.js';

// What an account's authorized keys file should hold between the lines that mark what Foundation manages for a host,
// and what a client found there after applying it. Everything outside those lines is left as it is. The first marking
// line names the generation of the plan last applied, and stays when no key is left, so that a client holding an older
// plan never writes over a newer one.

export const fingerprintOf = (key: string) =>
  'SHA256:' + createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64').replace(/=+$/, '');

const markers = (hostId: string) => ({
  begin: '# BEGIN FOUNDATION SSH ACCESS ' + Id.parse(hostId) + ' ',
  end: '# END FOUNDATION SSH ACCESS ' + Id.parse(hostId),
});

// The line letting a key in for an authorization, limited to where and until when it was let in.
export function authorizedKeyLine(entry: { id: string; publicKey: string; expiresAt: Date | null; from: string | null }) {
  const options = [
    ...(entry.from ? ['from="' + entry.from + '"'] : []),
    ...(entry.expiresAt ? ['expiry-time="' + entry.expiresAt.toISOString().replace(/[-:T]|\.\d+/g, '') + '"'] : []),
  ];
  return (options.length ? options.join(',') + ' ' : '') + sshKeyText(entry.publicKey).publicKey + ' foundation:' + Id.parse(entry.id);
}

// The words of a line, keeping quoted option values whole.
function words(line: string) {
  const result: string[] = [];
  let current = '', quoted = false;
  for (let index = 0; index < line.length; index++) {
    const character = line[index]!;
    if (character === '\\' && quoted && index + 1 < line.length) { current += character + line[++index]; continue; }
    if (character === '"') quoted = !quoted;
    if (!quoted && (character === ' ' || character === '\t')) {
      if (current) result.push(current);
      current = '';
    } else current += character;
  }
  if (current) result.push(current);
  return result;
}
const keyType = /^(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)(?:-cert-v01@openssh\.com)?$/;
// The fingerprint of the key a line lets in, or null for comments, blank lines, and lines sshd would not read as a key.
export function lineFingerprint(line: string) {
  const text = line.replace(/\r$/, '').trim();
  if (!text || text.startsWith('#')) return null;
  const parts = words(text), at = keyType.test(parts[0] ?? '') ? 0 : 1;
  const key = parts[at + 1];
  if (!keyType.test(parts[at] ?? '') || !key || !/^[A-Za-z0-9+/]+={0,2}$/.test(key)) return null;
  return fingerprintOf(key);
}

export class InvalidAuthorizedKeys extends Error {}
export class NewerAuthorizedKeys extends Error {}
// The file split around the host's managed lines; managed is null when the file has none yet.
function split(content: string, hostId: string) {
  const { begin, end } = markers(hostId);
  const lines = content === '' ? [] : content.replace(/\n$/, '').split('\n');
  const starts = lines.flatMap((line, index) => line.startsWith(begin) ? [index] : []);
  const ends = lines.flatMap((line, index) => line.replace(/\r$/, '') === end ? [index] : []);
  if (!starts.length && !ends.length) return { before: lines, managed: null, generation: null, after: [] as string[] };
  const invalid = () => new InvalidAuthorizedKeys('The managed lines for this host are not marked once from beginning to end.');
  if (starts.length !== 1 || ends.length !== 1 || ends[0]! < starts[0]!) throw invalid();
  const generation = /^(0|[1-9]\d{0,14})\r?$/.exec(lines[starts[0]!]!.slice(begin.length))?.[1];
  if (generation === undefined) throw invalid();
  return { before: lines.slice(0, starts[0]), managed: lines.slice(starts[0]! + 1, ends[0]), generation: Number(generation),
    after: lines.slice(ends[0]! + 1) };
}

// The file with the host's managed lines replaced by those of a plan, or added at the end. A file already holding a
// newer plan is left alone, and an empty file without managed lines is left empty.
export function withManagedLines(content: string, hostId: string, lines: string[], generation: number) {
  const { begin, end } = markers(hostId), parts = split(content, hostId);
  if (parts.generation !== null && parts.generation > generation)
    throw new NewerAuthorizedKeys('A newer plan was applied to this account.');
  if (parts.managed === null && !lines.length) return content;
  for (const line of lines) if (line.includes('\n') || line.includes('\r')) throw new InvalidAuthorizedKeys('Use one line for each key.');
  return [...parts.before, begin + generation, ...lines, end, ...parts.after].join('\n') + '\n';
}

// What the file lets in for the host: the managed lines as they are, and the fingerprints of keys let in elsewhere.
export function inspectAuthorizedKeys(content: string, hostId: string) {
  const parts = split(content, hostId);
  const unmanaged = new Set([...parts.before, ...parts.after].map(lineFingerprint).filter(value => value !== null));
  return { managed: (parts.managed ?? []).map(line => line.replace(/\r$/, '')).filter(line => line.trim() && !line.trim().startsWith('#')),
    unmanaged: [...unmanaged].sort() };
}

// The authorized keys a client applies to each account of a host, read with the host's update permission.
export const SSHPlanAccount = z.object({
  account: SSHAccount, file: AuthorizedKeysFile, generation: z.number().int().nonnegative(), lines: z.array(z.string()),
}).strict();
export const SSHPlan = z.object({
  hostId: Id, address: SSHAddress, port: z.number().int().min(1).max(65535), hostKeys: z.array(SSHPublicKey).min(1),
  accounts: z.array(SSHPlanAccount),
}).strict();
export type SSHPlan = z.infer<typeof SSHPlan>;
export const SSHOutcome = z.enum(['verified', 'conflict', 'unreachable', 'denied', 'host_key_mismatch', 'invalid_file', 'failed']);
// What a client found on an account: verified with the lines it read back, or why it could not apply or read them.
export const SSHReport = z.discriminatedUnion('outcome', [
  z.object({ account: SSHAccount, generation: z.number().int().nonnegative(), outcome: z.literal('verified'),
    managed: z.array(z.string().max(16384)).max(1000), unmanaged: z.array(SSHFingerprint).max(1000) }).strict(),
  z.object({ account: SSHAccount, generation: z.number().int().nonnegative(), outcome: SSHOutcome.exclude(['verified']),
    message: z.string().max(1000).optional() }).strict(),
]);
export type SSHReport = z.infer<typeof SSHReport>;
