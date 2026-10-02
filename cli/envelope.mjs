import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';

// How a secret is kept so that only those it was handed to can open it. Each secret has a key of its own (K);
// its bytes are sealed with K, and K is sealed once per recipient with that recipient's public key: an
// envelope. Whoever holds the private key opens the envelope and then the bytes; nobody else, and not the
// server, which keeps only sealed bytes and envelopes. A recipient's private key is itself kept sealed by
// a key that only one of its WebAuthn credentials yields (its PRF output), or in a file it keeps itself.
//
// Keys are X25519; sealing is AES-256-GCM; the envelope key comes from HKDF-SHA256 over the ephemeral
// agreement. Every form is bytes: iv (12) + tag (16) + ciphertext, with the ephemeral public key (32) in
// front for an envelope. A browser does the same with Web Crypto.
const SPKI = Buffer.from('302a300506032b656e032100', 'hex'), PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const ENVELOPE_INFO = 'foundation-envelope', WRAP_INFO = 'foundation-key';

export function generateKey() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return { privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32), publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32) };
}
export const publicKeyOf = privateKey => createPublicKey(toPrivate(privateKey)).export({ type: 'spki', format: 'der' }).subarray(-32);
const toPublic = raw => createPublicKey({ key: Buffer.concat([SPKI, raw]), type: 'spki', format: 'der' });
const toPrivate = raw => createPrivateKey({ key: Buffer.concat([PKCS8, raw]), type: 'pkcs8', format: 'der' });

function sealWith(key, bytes, aad) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const content = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), content]);
}
function openWith(key, sealed, aad) {
  if (sealed.length < 28) throw new Error('sealed bytes are too short');
  const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12));
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(12, 28));
  return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
}
const agree = (privateKey, publicKey, info) => Buffer.from(hkdfSync('sha256', diffieHellman({ privateKey: toPrivate(privateKey), publicKey: toPublic(publicKey) }), '', info, 32));

// The secret's own key, and its bytes sealed with it.
export const newContentKey = () => randomBytes(32);
export const sealContent = (contentKey, bytes) => sealWith(contentKey, bytes);
export const openContent = (contentKey, sealed) => openWith(contentKey, sealed);

// K sealed for one recipient: an ephemeral key agrees with the recipient's, and the recipient's public key
// is bound in as associated data so an envelope opens only for whom it was made.
export function seal(contentKey, recipientPublicKey) {
  const ephemeral = generateKey();
  return Buffer.concat([ephemeral.publicKey, sealWith(agree(ephemeral.privateKey, recipientPublicKey, ENVELOPE_INFO), contentKey, recipientPublicKey)]);
}
export function open(envelope, privateKey) {
  if (envelope.length < 32 + 28) throw new Error('envelope is too short');
  return openWith(agree(privateKey, envelope.subarray(0, 32), ENVELOPE_INFO), envelope.subarray(32), publicKeyOf(privateKey));
}

// A private key sealed with what a credential yields, so that credential alone unseals it.
const wrapKey = yielded => Buffer.from(hkdfSync('sha256', yielded, '', WRAP_INFO, 32));
export const wrap = (privateKey, yielded) => sealWith(wrapKey(yielded), privateKey);
export const unwrap = (wrapped, yielded) => openWith(wrapKey(yielded), wrapped);
