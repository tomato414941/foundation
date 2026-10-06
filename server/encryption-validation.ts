import { decodeProtectedHeader } from 'jose';
import type { PublicEncryptionKey, SealedContent } from '../shared/contracts.js';
import { PublicKey } from '../shared/contracts.js';
import { fail } from './errors.js';

export function samePublicKey(left: PublicEncryptionKey | null, right: PublicEncryptionKey | null) {
  return left?.kty === right?.kty && left?.crv === right?.crv && left?.x === right?.x &&
    left?.y === right?.y;
}

export function validateRecipientKeys(
  sealed: SealedContent,
  recipients: Array<{ id: string; publicKey: PublicEncryptionKey }>,
) {
  let header;
  try { header = decodeProtectedHeader(sealed); }
  catch { fail(400, 'invalid_envelope', 'Use a valid encrypted envelope.'); }
  if (header.enc !== 'A256GCM') fail(400, 'invalid_envelope', 'Use A256GCM to encrypt content.');
  for (const recipient of sealed.recipients) {
    const key = recipients.find(item => item.id === recipient.header.kid)?.publicKey;
    const epk = PublicKey.safeParse(recipient.header.epk ?? header.epk);
    if ((recipient.header.alg ?? header.alg) !== 'ECDH-ES+A256KW' || !epk.success)
      fail(400, 'invalid_envelope', 'Use ECDH-ES+A256KW for each recipient.');
    if (!key || epk.data.crv !== key.crv)
      fail(409, 'encryption_key_changed', 'An encryption key changed. Reload before saving.');
  }
}
