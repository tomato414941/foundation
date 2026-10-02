// Sealing in the browser, the same forms as the CLI's envelope.mjs: a secret's bytes sealed with its own key (K),
// K sealed per recipient with X25519 and AES-256-GCM (an envelope), and a private key wrapped with what a passkey
// yields (its PRF output). Every form is bytes: iv (12) + tag (16) + ciphertext, with the ephemeral public key
// (32) in front of an envelope. Base64url at the API's edge.
const subtle = crypto.subtle;
const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const text = value => new TextEncoder().encode(value);
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0)); let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out; };

export const toBase64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromBase64url = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));

export async function generateKey() {
  const pair = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  return { publicKey: new Uint8Array(await subtle.exportKey('raw', pair.publicKey)), privateKey: new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)).slice(-32) };
}
const importPrivate = raw => subtle.importKey('pkcs8', concat(PKCS8, raw), { name: 'X25519' }, false, ['deriveBits']);
const importPublic = raw => subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
const aesKey = (raw, uses) => subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, uses);
async function hkdf(secret, info) {
  const base = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: text(info) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function agree(privateRaw, publicRaw, info) {
  const bits = await subtle.deriveBits({ name: 'X25519', public: await importPublic(publicRaw) }, await importPrivate(privateRaw), 256);
  return hkdf(new Uint8Array(bits), info);
}
// Web Crypto puts the tag after the ciphertext; the kept form puts it after the iv.
async function sealWith(key, bytes, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const out = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, key, bytes));
  return concat(iv, out.slice(-16), out.slice(0, -16));
}
async function openWith(key, sealed, aad) {
  if (sealed.length < 28) throw new Error('sealed bytes are too short');
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12), ...(aad ? { additionalData: aad } : {}) }, key, concat(sealed.slice(28), sealed.slice(12, 28))));
}

export const newContentKey = () => crypto.getRandomValues(new Uint8Array(32));
export const sealContent = async (contentKey, bytes) => sealWith(await aesKey(contentKey, ['encrypt']), bytes);
export const openContent = async (contentKey, sealed) => openWith(await aesKey(contentKey, ['decrypt']), sealed);

export async function seal(contentKey, recipientPublicKey) {
  const ephemeral = await generateKey();
  return concat(ephemeral.publicKey, await sealWith(await agree(ephemeral.privateKey, recipientPublicKey, 'foundation-envelope'), contentKey, recipientPublicKey));
}
export async function open(envelope, privateKey, publicKey) {
  if (envelope.length < 60) throw new Error('envelope is too short');
  return openWith(await agree(privateKey, envelope.slice(0, 32), 'foundation-envelope'), envelope.slice(32), publicKey);
}

export const wrap = async (privateKey, yielded) => sealWith(await hkdf(yielded, 'foundation-key'), privateKey);
export const unwrap = async (wrapped, yielded) => openWith(await hkdf(yielded, 'foundation-key'), wrapped);
