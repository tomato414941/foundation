import { z } from 'zod';

if (typeof window !== 'undefined') z.config({ jitless: true });

export function sshKeyBytes(value: string): Uint8Array | null {
  const match = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+[^\r\n\0]*)?$/.exec(value.trim());
  if (!match) return null;
  try {
    const bytes = Uint8Array.from(atob(match[2]!), character => character.charCodeAt(0));
    const view = new DataView(bytes.buffer);
    let offset = 0;
    const field = () => {
      if (offset + 4 > bytes.length) throw new Error('Invalid SSH key.');
      const length = view.getUint32(offset); offset += 4;
      if (offset + length > bytes.length) throw new Error('Invalid SSH key.');
      const result = bytes.subarray(offset, offset + length); offset += length;
      return result;
    };
    const text = (input: Uint8Array) => new TextDecoder().decode(input);
    if (text(field()) !== match[1]) return null;
    if (match[1] === 'ssh-ed25519') {
      if (field().length !== 32) return null;
    } else if (match[1] === 'ssh-rsa') {
      const exponent = field(), modulus = field();
      if (!exponent.length || modulus.length < 256 || modulus.length > 1025) return null;
    } else {
      const curve = text(field()), point = field();
      const sizes: Record<string, number> = { nistp256: 65, nistp384: 97, nistp521: 133 };
      if (match[1] !== 'ecdsa-sha2-' + curve || point[0] !== 4 || point.length !== sizes[curve]) return null;
    }
    return offset === bytes.length ? bytes : null;
  } catch { return null; }
}

export const SSHPublicKey = z.string().trim().max(8192).refine(value => sshKeyBytes(value) !== null,
  'Use an OpenSSH public key from a .pub file.');
export const SSHSettings = z.object({ authorizedKeys: z.array(SSHPublicKey).max(32) }).strict();
export const SSHUpdate = SSHSettings.extend({ revision: z.number().int().positive().optional() });
export const SSHConnection = SSHSettings.extend({
  host: z.string().min(1).max(253), port: z.number().int().min(1024).max(65535),
  username: z.literal('root'), workingDirectory: z.literal('/workspace'),
  hostKey: SSHPublicKey.nullable(), fingerprint: z.string().nullable(),
  revision: z.number().int().positive(), appliedRevision: z.number().int().nonnegative(),
  activeSessions: z.number().int().min(0).max(1024),
}).strict();
export const SSHView = SSHConnection.extend({ state: z.enum(['starting', 'configuring', 'ready', 'disabled', 'stopped']) });
export const SSHHeartbeat = z.object({
  hostKey: SSHPublicKey, appliedRevision: z.number().int().nonnegative(),
  activeSessions: z.number().int().min(0).max(1024),
}).strict();
export const SSHConfiguration = SSHSettings.extend({ port: z.number().int().min(1024).max(65535),
  revision: z.number().int().positive() }).strict();
export const SSHWorkerState = z.object({ configuration: SSHConfiguration.nullable() }).strict();
export type SSHConnectionInfo = z.infer<typeof SSHView>;

export function sshCommand(value: Pick<SSHConnectionInfo, 'host' | 'port' | 'username'>) {
  return 'ssh -p ' + value.port + ' ' + value.username + '@' + value.host;
}
