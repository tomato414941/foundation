import type { PublicEncryptionKey } from '../shared/contracts.js';

export function samePublicKey(left: PublicEncryptionKey | null, right: PublicEncryptionKey | null) {
  return left?.kty === right?.kty && left?.crv === right?.crv && left?.x === right?.x &&
    left?.y === right?.y;
}
