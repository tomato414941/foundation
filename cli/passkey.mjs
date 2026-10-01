import { createHash, generateKeyPairSync, createPrivateKey, randomBytes, sign } from 'node:crypto';

// A WebAuthn authenticator in software, for wherever there is no browser: it makes a passkey and answers challenges
// with it, writing what a browser writes. The origin it signs is the one it is actually talking to, so a challenge
// relayed from elsewhere is refused there. It reports the user present - the principal running it asked - and never
// verified, since it checks no face, fingerprint or PIN.
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const sha256 = data => createHash('sha256').update(data).digest();
const PRESENT = 0x01, ATTESTED = 0x40;

// Just enough CBOR (RFC 8949) for an attestation object and a COSE key: maps, byte and text strings, small integers.
function cbor(value) {
  const head = (major, length) => length < 24 ? Buffer.from([major << 5 | length])
    : length < 256 ? Buffer.from([major << 5 | 24, length]) : Buffer.from([major << 5 | 25, length >> 8, length & 255]);
  if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') { const text = Buffer.from(value); return Buffer.concat([head(3, text.length), text]); }
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([key, item]) => [cbor(key), cbor(item)])]);
}
const counter = count => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(count); return bytes; };
const clientData = (type, challenge, origin) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

// Makes a passkey for the options a server gave. Returns what to send back, and what to keep: the passkey's id, its
// private key, and whose it is.
export function createPasskey(options, origin) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const point = publicKey.export({ format: 'jwk' }), id = randomBytes(32);
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(point.x, 'base64url')], [-3, Buffer.from(point.y, 'base64url')]]));
  const authData = Buffer.concat([sha256(options.rp.id), Buffer.from([PRESENT | ATTESTED]), counter(0), Buffer.alloc(16),
    Buffer.from([id.length >> 8, id.length & 255]), id, cose]);
  const response = { id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {},
    response: { clientDataJSON: b64(clientData('webauthn.create', options.challenge, origin)), attestationObject: b64(cbor({ fmt: 'none', attStmt: {}, authData })), transports: [] } };
  return { response, passkey: { id: b64(id), user: options.user.id, private_key: privateKey.export({ format: 'jwk' }) } };
}

// Answers a sign-in challenge with a kept passkey.
export function answer(options, passkey, origin) {
  const data = clientData('webauthn.get', options.challenge, origin);
  const authData = Buffer.concat([sha256(options.rpId), Buffer.from([PRESENT]), counter(0)]);
  const signature = sign('sha256', Buffer.concat([authData, sha256(data)]), createPrivateKey({ key: passkey.private_key, format: 'jwk' }));
  return { id: passkey.id, rawId: passkey.id, type: 'public-key', clientExtensionResults: {},
    response: { clientDataJSON: b64(data), authenticatorData: b64(authData), signature: b64(signature), userHandle: passkey.user } };
}
