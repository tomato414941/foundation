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
// The algorithm and key of an OpenSSH public key, without its comment.
export function sshKeyText(value: string) {
  if (!sshKeyBytes(value)) throw new Error('Use an OpenSSH public key from a .pub file.');
  const [algorithm, key] = value.trim().split(/[ \t]+/);
  return { algorithm: algorithm!, key: key!, publicKey: algorithm + ' ' + key };
}
// An account on a server, named as OpenSSH signs in as it.
export const SSHAccount = z.string().max(32).regex(/^[a-z_][a-z0-9_-]*$/, 'Use a lowercase account name.');
export const SSHAddress = z.string().min(1).max(253).regex(/^[A-Za-z0-9_.:]+(?:-[A-Za-z0-9_.:]+)*$/, 'Use a host name or IP address.');
export const SSHFingerprint = z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/);
