import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { Database } from '../server/database.js';

const sha256 = (value: Buffer) => createHash('sha256').update(value).digest();

// A passkey held by a software authenticator, which answers WebAuthn requests as a browser would.
export function softwarePasskey(origin: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.from(isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])));
  const rawId = randomBytes(16), identifier = rawId.toString('base64url'), rpIdHash = sha256(Buffer.from(new URL(origin).hostname));
  let counter = 0;
  const counted = () => { const value = Buffer.alloc(4); value.writeUInt32BE(++counter); return value; };
  const client = (type: string, challenge: string) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    identifier,
    cose,
    register(options: { challenge: string }) {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(rawId.length);
      const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([0x45]), counted(), Buffer.alloc(16), length, rawId, cose]);
      const attestationObject = Buffer.from(isoCBOR.encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()],
        ['authData', authenticatorData]]) as never));
      return { id: identifier, rawId: identifier, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: client('webauthn.create', options.challenge).toString('base64url'),
          attestationObject: attestationObject.toString('base64url'), transports: ['internal'] } };
    },
    assert(options: { challenge: string }) {
      const clientDataJSON = client('webauthn.get', options.challenge);
      const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([0x05]), counted()]);
      const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
      return { id: identifier, rawId: identifier, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'),
          signature: signature.toString('base64url') } };
    },
  };
}

// A passkey of the principal, registered as if added earlier.
export async function addPasskey(db: Database, principalId: string, origin: string, wrap: string | null = null) {
  const passkey = softwarePasskey(origin), id = randomUUID();
  await db.pool.query("INSERT INTO credentials(id,principal_id,kind,name,identifier,data,private_wrap) VALUES($1,$2,'passkey','Test passkey',$3,$4,$5)",
    [id, principalId, passkey.identifier, JSON.stringify({ publicKey: passkey.cose.toString('base64url'), counter: 0, transports: [], backedUp: false }), wrap]);
  return { id, assert: passkey.assert };
}
