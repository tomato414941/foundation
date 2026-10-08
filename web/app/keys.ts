import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import { importJWK } from 'jose';
import type { PrincipalView, PublicEncryptionKey } from '../../shared/contracts';
import { base64url, encode, hold, unwrap, wrap } from '../../shared/encryption';
import { PrivateKeys, SignedBinding, bindKeys, canonical, completeKeys, newIdentityKeys, publicPart, signBinding } from '../../shared/authority';
import type { BoundKeys, IdentityKeys } from '../../shared/authority';
import { api, ApiFailure } from './api';
import { listOf } from '../../shared/contracts';
import { KeySharingItem } from '../../shared/protocol';
import { protect } from '../../shared/custody';
import type { CustodyContent } from '../../shared/custody';
import { stored } from './storage';

const unlocked = new Map<string, IdentityKeys>();
type HeldIdentity = { binding: BoundKeys; keys: { encryption: CryptoKey; signing: CryptoKey } };
const held = new Map<string, HeldIdentity>();
const seed = encode('Foundation passkey identity keys v2');
// Keys wrapped before signing keys existed were derived from this seed; sign-in still asks for it
// so such a wrap can be opened once and replaced.
const formerSeed = encode('Foundation passkey encryption v1');
type Verified = {
  principalId: string;
  credentialId: string;
  wrappedKey: string | null;
  publicKey: PublicEncryptionKey | null;
  returnTo: string;
};
export async function getIdentity(id: string): Promise<HeldIdentity | null> {
  const identity = held.get(id) ?? await stored('keys', 'readonly', store => store.get('v2:' + id));
  if (!identity?.keys || identity.binding?.principalId !== id ||
    !(identity.keys.encryption instanceof CryptoKey) || !(identity.keys.signing instanceof CryptoKey)) return null;
  held.set(id, identity);
  return identity;
}
export async function getKey(id: string, publicKey?: PublicEncryptionKey | null): Promise<CryptoKey | null> {
  const identity = await getIdentity(id);
  if (!identity || (publicKey && canonical(identity.binding.encryption) !== canonical(publicKey))) return null;
  return identity.keys.encryption;
}
function matchesPublicKey(keys: IdentityKeys, publicKey: PublicEncryptionKey | null) {
  return publicKey && canonical(publicPart(keys.encryption)) === canonical(publicKey);
}
async function keep(id: string, keys: IdentityKeys) {
  let binding: BoundKeys;
  try {
    const existing = await api('/identities/' + id + '/binding', {}, SignedBinding);
    await signBinding(existing.binding, keys);
    binding = existing.binding;
  } catch (error) {
    if (!(error instanceof ApiFailure) || error.code !== 'key_binding_required') throw error;
    binding = bindKeys(id, keys);
    await api('/principals/' + id + '/binding', { method: 'PUT', body: await signBinding(binding, keys) }, SignedBinding);
  }
  const previous = await getIdentity(id);
  if (previous && canonical(previous.binding) !== canonical(binding)) throw new ApiFailure('encryption_key_changed');
  const signing = await importJWK(keys.signing, 'ES256', { extractable: false });
  if (!(signing instanceof CryptoKey)) throw new ApiFailure('key_unavailable');
  const identity = { binding, keys: { encryption: await hold(keys.encryption), signing } };
  await stored('keys', 'readwrite', store => store.put(identity, 'v2:' + id));
  held.set(id, identity);
  unlocked.set(id, keys);
}
export async function clearKeys() {
  unlocked.clear();
  held.clear();
  await stored('keys', 'readwrite', (store) => store.clear());
}
function prf(credential: AuthenticationResponseJSON | RegistrationResponseJSON): Uint8Array | null {
  const output = credential.clientExtensionResults as { prf?: { results?: { first?: ArrayBuffer } } };
  const value = output.prf?.results?.first;
  return value ? new Uint8Array(value) : null;
}
function formerPrf(credential: AuthenticationResponseJSON): Uint8Array | null {
  const output = credential.clientExtensionResults as { prf?: { results?: { second?: ArrayBuffer } } };
  const value = output.prf?.results?.second;
  return value ? new Uint8Array(value) : null;
}
function verificationCredential(credential: AuthenticationResponseJSON | RegistrationResponseJSON) {
  const { prf: _prf, ...extensions } = credential.clientExtensionResults as Record<string, unknown>;
  return { ...credential, clientExtensionResults: extensions };
}
async function assertion(principalId?: string, credentialId?: string) {
  const data = await api<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }>(
    '/auth/passkeys/options',
    { method: 'POST', body: { intent: 'authenticate', ...(principalId ? { principalId } : {}) } },
  );
  const options = {
    ...data.options,
    extensions: { ...data.options.extensions, prf: { eval: { first: seed, second: formerSeed } } },
    ...(credentialId ? { allowCredentials: [{ id: credentialId, type: 'public-key' as const }] } : {}),
  };
  const credential = await startAuthentication({ optionsJSON: options });
  return { challengeId: data.challengeId, credential, secret: prf(credential), formerSecret: formerPrf(credential) };
}
export async function authenticate(principalId?: string, credentialId?: string, wrapping?: IdentityKeys) {
  const proof = await assertion(principalId, credentialId);
  const result = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST',
    body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) },
  });
  if (proof.secret) {
    if (result.wrappedKey) {
      let unwrapped: unknown, former = false;
      try {
        unwrapped = await unwrap(result.wrappedKey, proof.secret, result.principalId);
      } catch {
        if (!proof.formerSecret) throw new ApiFailure('key_unavailable');
        unwrapped = await unwrap(result.wrappedKey, proof.formerSecret, result.principalId).catch(() => {
          throw new ApiFailure('key_unavailable');
        });
        former = true;
      }
      const { keys: key, completed } = await completeKeys(unwrapped).catch(() => {
        throw new ApiFailure('key_unreadable');
      });
      if (!matchesPublicKey(key, result.publicKey)) throw new ApiFailure('encryption_key_changed');
      if (completed || former)
        await api(`/principals/${result.principalId}/credentials/${result.credentialId}/wrap`, {
          method: 'PUT',
          body: { wrappedKey: await wrap(key, proof.secret, result.principalId), publicKey: result.publicKey },
        });
      await keep(result.principalId, key);
    } else if (!result.publicKey || wrapping) {
      if (wrapping && result.publicKey && !matchesPublicKey(wrapping, result.publicKey))
        throw new ApiFailure('encryption_key_changed');
      const keys = wrapping ?? await newIdentityKeys();
      const publicKey = publicPart(keys.encryption);
      const wrappedKey = await wrap(keys, proof.secret, result.principalId);
      if (!result.publicKey)
        await api(`/principals/${result.principalId}/encryption-key`, {
          method: 'PUT',
          body: { publicKey, wraps: { [result.credentialId]: wrappedKey } },
        });
      else
        await api(`/principals/${result.principalId}/credentials/${result.credentialId}/wrap`, {
          method: 'PUT',
          body: { wrappedKey, publicKey: result.publicKey },
        });
      await keep(result.principalId, keys);
    }
  }
  return { ...result, encrypted: !!(await getKey(result.principalId)) };
}
export async function registerPasskey(name: string, principal?: Pick<PrincipalView, 'id' | 'publicKey'>) {
  let existing = principal ? unlocked.get(principal.id) : undefined;
  if (existing && !matchesPublicKey(existing, principal!.publicKey)) existing = undefined;
  if (principal?.publicKey && !existing) {
    await authenticate(principal.id);
    existing = unlocked.get(principal.id);
    if (!existing) throw new ApiFailure('key_unavailable');
  }
  const data = await api<{
    challengeId: string;
    principalId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>('/auth/passkeys/options', {
    method: 'POST',
    body: { intent: 'register', name, ...(principal ? { principalId: principal.id } : {}) },
  });
  const credential = await startRegistration({
    optionsJSON: {
      ...data.options,
      extensions: { ...data.options.extensions, prf: { eval: { first: seed } } },
    },
  });
  const secret = prf(credential);
  const keys = secret ? existing ?? await newIdentityKeys() : null;
  const publicKey = keys ? publicPart(keys.encryption) : null;
  const wrappedKey = secret && keys ? await wrap(keys, secret, data.principalId) : undefined;
  const result = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST',
    body: {
      challengeId: data.challengeId,
      credential: verificationCredential(credential),
      ...(keys ? { wrappedKey, ...(!principal?.publicKey ? { publicKey } : { existingPublicKey: publicKey }) } : {}),
    },
  });
  if (keys) await keep(result.principalId, keys);
  else if ((credential.clientExtensionResults as { prf?: { enabled?: boolean } }).prf?.enabled)
    return authenticate(result.principalId, credential.id, existing);
  return { ...result, encrypted: !!(await getKey(result.principalId)) };
}
export async function issueKey(
  principal: Pick<PrincipalView, 'id' | 'publicKey'>,
  name: string,
  expiresAt: string | null,
) {
  let existing = unlocked.get(principal.id);
  if (existing && !matchesPublicKey(existing, principal.publicKey)) existing = undefined;
  if (principal.publicKey && !existing) {
    await authenticate(principal.id);
    existing = unlocked.get(principal.id);
    if (!existing) throw new ApiFailure('key_unavailable');
  }
  const issued = await api<{ credential: { id: string }; token: string }>(
    `/principals/${principal.id}/credentials`,
    { method: 'POST', body: { name, expiresAt } },
  );
  const keys = existing ?? await newIdentityKeys(), publicKey = publicPart(keys.encryption);
  const unlock = crypto.getRandomValues(new Uint8Array(32));
  const wrappedKey = await wrap(keys, unlock, principal.id);
  if (existing)
    await api(`/principals/${principal.id}/credentials/${issued.credential.id}/wrap`, {
      method: 'PUT',
      body: { wrappedKey, publicKey },
    });
  else
    await api(`/principals/${principal.id}/encryption-key`, {
      method: 'PUT',
      body: { publicKey, wraps: { [issued.credential.id]: wrappedKey } },
    });
  await keep(principal.id, keys);
  return { token: issued.token + '.' + base64url(unlock) };
}
export async function decryptSecret(id: string, principalId: string) {
  const { custodyClient } = await import('./custody');
  return (await custodyClient(principalId)).reveal(id);
}

export async function mergeWithPasskey() {
  const proof = await assertion();
  const result = await api<{ id: string; fromId: string; wrappedKey: string | null; publicKey: PublicEncryptionKey | null }>(
    '/account/merge/passkey',
    {
      method: 'POST',
      body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) },
    },
  );
  if (result.wrappedKey && proof.secret)
    await keep(result.fromId, PrivateKeys.parse(await unwrap(result.wrappedKey, proof.secret, result.fromId)));
  return result;
}

export async function rekeySharing(path: string) {
  const plan = await api(path, {}, listOf(KeySharingItem));
  const updates: Record<string, { version: number; content: CustodyContent }> = {};
  if (!plan.items.length) return updates;
  const { custodyClient } = await import('./custody');
  const client = await custodyClient();
  for (const item of plan.items) {
    const current = await client.read(item.id);
    if (current.version !== item.version || canonical(current.content) !== canonical(item.content))
      throw new ApiFailure('changed');
    for (const recipient of item.policy.readers) await client.trusted(recipient);
    updates[item.id] = { version: item.version,
      content: await protect(await client.reveal(item.id), item.policy, item.content.materialRevision + 1,
        client.binding, client.keys, item.content.metadata, item.content) };
  }
  return updates;
}
