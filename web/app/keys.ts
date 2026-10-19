import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import { importJWK } from 'jose';
import type { JWK } from 'jose';
import type { PrincipalView, PublicEncryptionKey, SealedContent } from '../../shared/contracts';
import { base64url, decode, encode, hold, newEncryptionKey, open, unbase64url, unwrap, wrap } from '../../shared/encryption';
import { Session } from '../../shared/session';
import { PrivateKeys, SignedBinding, bindKeys, canonical, newIdentityKeys, publicPart, signBinding } from '../../shared/authority';
import type { BoundKeys, IdentityKeys } from '../../shared/authority';
import { api, ApiFailure, session } from './api';
import { stored } from './storage';
import { useSyncExternalStore } from 'react';
import { Resource, listOf } from '../../shared/contracts';
import { KeySharingItem } from '../../shared/protocol';

const unlocked = new Map<string, IdentityKeys>();
type HeldIdentity = { binding: BoundKeys; keys: { encryption: CryptoKey; signing: CryptoKey } };
const held = new Map<string, HeldIdentity>();
const seed = encode('Foundation passkey identity keys v2');
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
// The private key this browser holds for the principal while it is still the principal's: one replaced by new keys is
// forgotten here.
export async function heldKeys(principal: Pick<PrincipalView, 'id' | 'publicKey'>) {
  const identity = await getIdentity(principal.id);
  if (!identity) return null;
  if (principal.publicKey && canonical(identity.binding.encryption) === canonical(principal.publicKey)) return identity;
  await forget(principal.id);
  return null;
}
async function forget(id: string) {
  held.delete(id);
  unlocked.delete(id);
  await stored('keys', 'readwrite', store => store.delete('v2:' + id));
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
  reprotectInBackground(id);
}
// How many items this browser last sealed again for a principal, and those it could not, by name, and why.
export type Resealing = { done: number; failed: Array<{ id: string; name: string | null; code: string }> };
const resealing = new Map<string, Resealing>(), watching = new Set<() => void>();
// One pass at a time for each principal: a pass asked for while another runs starts after it, so that the two never
// seal the same item at once. An operation that opens the private key starts one in the background and then its own.
const passes = new Map<string, Promise<Resealing | null>>();
function reseal(id: string) {
  const pass = (passes.get(id) ?? Promise.resolve(null)).catch(() => null).then(() => sealPending(id));
  passes.set(id, pass);
  return pass;
}
async function sealPending(id: string) {
  if (!(await getIdentity(id))) return null;
  const { custodyClient } = await import('./custody');
  const { done, failed } = await (await custodyClient(id)).reprotectPending();
  const outcome = { done: done.length, failed: await Promise.all(failed.map(async item => ({ ...item,
    name: await api('/resources/' + item.id, {}, Resource).then(resource => resource.name, () => null) }))) };
  resealing.set(id, outcome);
  for (const notify of watching) notify();
  return outcome;
}
// Whenever this browser holds a principal's keys, it seals again the items the server lists as
// needing it. Each principal is handled once per page load, so an item left now is tried again next time.
const reprotecting = new Set<string>();
export function reprotectInBackground(id: string) {
  if (reprotecting.has(id)) return;
  reprotecting.add(id);
  void reseal(id).then(outcome => { if (!outcome) reprotecting.delete(id); }, (error: unknown) => {
    reprotecting.delete(id);
    console.warn('The items to seal again could not be checked.', error);
  });
}
// Seals the items again at once, as after a line changes who may open them.
export async function resealNow(id: string) {
  reprotecting.add(id);
  return reseal(id);
}
export function useResealing(id: string | undefined) {
  return useSyncExternalStore(notify => { watching.add(notify); return () => watching.delete(notify); },
    () => (id ? resealing.get(id) ?? null : null), () => null);
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
function verificationCredential(credential: AuthenticationResponseJSON | RegistrationResponseJSON) {
  const { prf: _prf, ...extensions } = credential.clientExtensionResults as Record<string, unknown>;
  return { ...credential, clientExtensionResults: extensions };
}
// For a principal, the server offers only the passkeys that hold its private key, or the one passkey named.
async function assertion(principalId?: string, credentialId?: string) {
  const data = await api<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }>(
    '/auth/passkeys/options',
    { method: 'POST', body: { intent: 'authenticate', ...(principalId ? { principalId } : {}), ...(credentialId ? { credentialId } : {}) } },
  );
  const options = {
    ...data.options,
    extensions: { ...data.options.extensions, prf: { eval: { first: seed } } },
  };
  const credential = await startAuthentication({ optionsJSON: options });
  return { challengeId: data.challengeId, credential, secret: prf(credential) };
}
// Signs in with a passkey and keeps the private key it opens. The reason says why it opened none: this passkey or
// browser cannot give the secret that opens it, or the private key is not wrapped for this passkey.
export async function authenticate(principalId?: string, credentialId?: string, wrapping?: IdentityKeys) {
  const proof = await assertion(principalId, credentialId);
  const result = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST',
    body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) },
  });
  let reason: string | null = null;
  if (!proof.secret) reason = 'key_unsupported';
  else if (result.wrappedKey) {
    const unwrapped = await unwrap(result.wrappedKey, proof.secret, result.principalId).catch(() => {
      throw new ApiFailure('key_unavailable');
    });
    const keys = PrivateKeys.safeParse(unwrapped);
    if (!keys.success) throw new ApiFailure('key_unavailable');
    if (!matchesPublicKey(keys.data, result.publicKey)) throw new ApiFailure('encryption_key_changed');
    await keep(result.principalId, keys.data);
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
  } else reason = 'wrapped_key_required';
  return { ...result, encrypted: !!(await getKey(result.principalId)), reason };
}
// Opens the principal's private key with one of its passkeys that holds it, for this browser to keep, or says why
// it could not.
export async function openKeys(id: string) {
  const { reason } = await authenticate(id);
  if (reason) throw new ApiFailure(reason);
}
// An operation the user started calls this before it uses the private key, so that one of the principal's passkeys
// opens it when this browser does not hold it. Opening a page or work in the background never asks for a passkey.
export async function requireKeys(id?: string) {
  const principalId = id ?? (await session()).principal?.id;
  if (!principalId) throw new ApiFailure('unauthenticated');
  if (!(await getIdentity(principalId))) await openKeys(principalId);
}
// The private keys themselves, to wrap them for another passkey or an API key. They stay readable only in the page
// where a passkey opened them, so a passkey that holds them is asked for otherwise.
async function privateKeys(principal: Pick<PrincipalView, 'id' | 'publicKey'>) {
  const kept = unlocked.get(principal.id);
  if (kept && matchesPublicKey(kept, principal.publicKey)) return kept;
  await openKeys(principal.id);
  const keys = unlocked.get(principal.id);
  if (!keys || !matchesPublicKey(keys, principal.publicKey)) throw new ApiFailure('encryption_key_changed');
  return keys;
}
export async function registerPasskey(name: string, principal?: Pick<PrincipalView, 'id' | 'publicKey'>) {
  const existing = principal?.publicKey ? await privateKeys(principal) : undefined;
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
    return authenticate(result.principalId, result.credentialId, existing);
  return { ...result, encrypted: !!(await getKey(result.principalId)) };
}
// Makes new keys once the request to make them is ready. A new passkey is registered first and the session signs in with
// it; the private key it then keeps replaces the principal's, and the new keys are published as for one that had none.
export async function resetKeys(name: string, principalId: string) {
  const data = await api<{ challengeId: string; options: PublicKeyCredentialCreationOptionsJSON }>('/auth/passkeys/options', {
    method: 'POST', body: { intent: 'register', name, principalId },
  });
  const credential = await startRegistration({
    optionsJSON: { ...data.options, extensions: { ...data.options.extensions, prf: { eval: { first: seed } } } },
  });
  const registered = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST', body: { challengeId: data.challengeId, credential: verificationCredential(credential) },
  });
  let secret = prf(credential);
  // Some passkeys give the secret only when signing in with them.
  if (!secret && (credential.clientExtensionResults as { prf?: { enabled?: boolean } }).prf?.enabled) {
    const proof = await assertion(principalId, registered.credentialId);
    await api('/auth/passkeys/verify', {
      method: 'POST', body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) },
    });
    secret = proof.secret;
  }
  if (!secret) throw new ApiFailure('key_unsupported');
  const keys = await newIdentityKeys();
  await api(`/principals/${principalId}/key-reset/complete`, {
    method: 'POST', body: { publicKey: publicPart(keys.encryption), wrappedKey: await wrap(keys, secret, principalId) },
  });
  await forget(principalId);
  await keep(principalId, keys);
}
export async function issueKey(
  principal: Pick<PrincipalView, 'id' | 'publicKey'>,
  name: string,
  expiresAt: string | null,
) {
  const existing = principal.publicKey ? await privateKeys(principal) : undefined;
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
// Another device that holds the private key lets this browser in, the way it lets in the CLI: it issues an API key
// carrying the private key and seals the key's token to this browser's one-time public key.
export type Receiving = { id: string; code: string; poll: string; url: string; expiresAt: string; privateKey: JWK };
export async function startReceiving(name: string): Promise<Receiving> {
  const device = await newEncryptionKey();
  const started = await api<Omit<Receiving, 'privateKey'>>('/auth/devices', {
    method: 'POST',
    body: { name, publicKey: device.publicKey },
  });
  return { ...started, privateKey: device.privateKey };
}
// Keeps the private key once the other device answered, and removes the API key it issued for this, which nothing
// else uses. Returns false while the other device has not answered.
export async function receiveKeys(receiving: Receiving, principalId: string) {
  const polled = await api<{ state: string; principalId: string | null; sealed: SealedContent | null }>(
    `/auth/devices/${receiving.id}?poll=${encodeURIComponent(receiving.poll)}`,
  );
  if (polled.state !== 'approved' || !polled.sealed) return false;
  if (polled.principalId !== principalId) throw new ApiFailure('another_principal');
  const [token, unlock] = decode(await open(polled.sealed, receiving.privateKey, receiving.id, 'device:' + receiving.id))
    .split('.') as [string, string];
  const asKey = async (path: string, method = 'GET') => {
    const response = await fetch('/api' + path, { method, credentials: 'omit', headers: { authorization: 'Bearer ' + token } });
    if (!response.ok) throw new ApiFailure('key_unavailable', response.status);
    return response.status === 204 ? null : response.json() as Promise<unknown>;
  };
  const current = Session.parse(await asKey('/session'));
  if (!current.wrappedKey || !current.credentialId || current.principal?.id !== principalId)
    throw new ApiFailure('key_unavailable');
  const keys = PrivateKeys.safeParse(await unwrap(current.wrappedKey, unbase64url(unlock), principalId).catch(() => null));
  if (!keys.success) throw new ApiFailure('key_unavailable');
  if (!matchesPublicKey(keys.data, current.principal.publicKey)) throw new ApiFailure('encryption_key_changed');
  await asKey(`/principals/${principalId}/credentials/${current.credentialId}`, 'DELETE');
  await keep(principalId, keys.data);
  return true;
}
export async function decryptVariable(id: string, principalId: string) {
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
  if (!plan.items.length) return {};
  await requireKeys();
  const { custodyClient } = await import('./custody');
  return (await custodyClient()).sharing(plan.items);
}
