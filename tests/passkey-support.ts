import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { Database } from '../server/database.js';

const sha256 = (value: Buffer) => createHash('sha256').update(value).digest();

// A passkey of the principal held by a software authenticator, which answers WebAuthn requests as a browser would.
export async function addPasskey(db: Database, principalId: string, origin: string, wrap: string | null = null) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
  const id = randomUUID(), identifier = randomBytes(16).toString('base64url');
  await db.pool.query("INSERT INTO credentials(id,principal_id,kind,name,identifier,data,private_wrap) VALUES($1,$2,'passkey','Test passkey',$3,$4,$5)",
    [id, principalId, identifier, JSON.stringify({ publicKey: Buffer.from(cose).toString('base64url'), counter: 0, transports: [], backedUp: false }), wrap]);
  let counter = 0;
  return {
    id,
    assert(options: { challenge: string }) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
      const counted = Buffer.alloc(4);
      counted.writeUInt32BE(++counter);
      const authenticatorData = Buffer.concat([sha256(Buffer.from(new URL(origin).hostname)), Buffer.from([0x05]), counted]);
      const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
      return { id: identifier, rawId: identifier, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'),
          signature: signature.toString('base64url') } };
    },
  };
}
