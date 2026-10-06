import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import type { JWK } from 'jose';
import type { PrincipalView, PublicEncryptionKey, SealedContent } from '../../shared/contracts';
import { encode, hold, newEncryptionKey, open, seal, unwrap, wrap } from '../../shared/encryption';
import { api, ApiFailure, session } from './api';
import { KeySharingItem, PublicKey, listOf } from '../../shared/contracts';
import { KeyMigrationPlan } from '../../shared/key-migration';
import type { KeyMigrationInput } from '../../shared/key-migration';

const unlocked = new Map<string, JWK>();
const held = new Map<string, CryptoKey>();
const seed = encode('Foundation passkey encryption v1');
const legacySeed = encode('foundation-key');
type Verified = {
  principalId: string;
  credentialId: string;
  wrappedKey: string | null;
  publicKey: PublicEncryptionKey | null;
  returnTo: string;
};
function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('foundation-keys', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function stored<T>(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await database();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction('keys', mode);
      const request = operation(transaction.objectStore('keys'));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
}
export async function getKey(id: string, publicKey?: PublicEncryptionKey | null): Promise<CryptoKey | null> {
  const key = (
    held.get(id) ??
    ((await stored('readonly', (store) => store.get(id)).catch(() => null)) as CryptoKey | null)
  );
  if (key && publicKey && (key.algorithm.name === 'X25519' ? 'X25519' : (key.algorithm as EcKeyAlgorithm).namedCurve) !== publicKey.crv) {
    await forget(id);
    return null;
  }
  return key;
}
async function forget(id: string) {
  held.delete(id);
  unlocked.delete(id);
  await stored('readwrite', store => store.delete(id)).catch(() => {});
}
function matchesPublicKey(key: JWK, publicKey: PublicEncryptionKey | null) {
  return publicKey && key.kty === publicKey.kty && key.crv === publicKey.crv && key.x === publicKey.x &&
    (publicKey.kty !== 'EC' || key.y === publicKey.y);
}
async function keep(id: string, key: JWK) {
  const cryptoKey = await hold(key);
  held.set(id, cryptoKey);
  unlocked.set(id, key);
  await stored('readwrite', (store) => store.put(cryptoKey, id)).catch(() => {});
}
export async function clearKeys() {
  unlocked.clear();
  held.clear();
  await stored('readwrite', (store) => store.clear()).catch(() => {});
}
function prf(credential: AuthenticationResponseJSON | RegistrationResponseJSON, slot: 'first' | 'second' = 'first'): Uint8Array | null {
  const output = credential.clientExtensionResults as { prf?: { results?: { first?: ArrayBuffer; second?: ArrayBuffer } } };
  const value = output.prf?.results?.[slot];
  return value ? new Uint8Array(value) : null;
}
function verificationCredential(credential: AuthenticationResponseJSON | RegistrationResponseJSON) {
  const { prf: _prf, ...extensions } = credential.clientExtensionResults as Record<string, unknown>;
  return { ...credential, clientExtensionResults: extensions };
}
async function assertion(principalId?: string, credentialId?: string, includeLegacy = true) {
  const data = await api<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }>(
    '/auth/passkeys/options',
    { method: 'POST', body: { intent: 'authenticate', ...(principalId ? { principalId } : {}) } },
  );
  const options = {
    ...data.options,
    extensions: { ...data.options.extensions, prf: { eval: { first: seed, ...(includeLegacy ? { second: legacySeed } : {}) } } },
    ...(credentialId ? { allowCredentials: [{ id: credentialId, type: 'public-key' as const }] } : {}),
  };
  const credential = await startAuthentication({ optionsJSON: options });
  return { challengeId: data.challengeId, credential, secret: prf(credential), legacySecret: prf(credential, 'second') };
}
export async function authenticate(principalId?: string, credentialId?: string, wrapping?: JWK, includeLegacy = true) {
  const proof = await assertion(principalId, credentialId, includeLegacy);
  const result = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST',
    body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) },
  });
  if (proof.secret) {
    if (result.wrappedKey) {
      const legacy = result.wrappedKey.startsWith('x25519:');
      const secret = legacy ? proof.legacySecret : proof.secret;
      if (!secret) throw new ApiFailure('key_unavailable');
      const key = await unwrap(result.wrappedKey, secret, result.principalId, result.publicKey).catch(() => {
        throw new ApiFailure('key_unavailable');
      });
      if (!matchesPublicKey(key, result.publicKey)) throw new ApiFailure('encryption_key_changed');
      await keep(result.principalId, key);
      if (legacy) {
        const wrappedKey = await wrap(key, proof.secret, result.principalId);
        await api(`/principals/${result.principalId}/credentials/${result.credentialId}/wrap`, {
          method: 'PUT', body: { wrappedKey, publicKey: result.publicKey },
        });
      }
    } else if (!result.publicKey || wrapping) {
      if (wrapping && result.publicKey && !matchesPublicKey(wrapping, result.publicKey))
        throw new ApiFailure('encryption_key_changed');
      const pair = wrapping
        ? {
            privateKey: wrapping,
            publicKey: PublicKey.parse(wrapping.kty === 'OKP'
              ? { kty: 'OKP', crv: 'X25519', x: wrapping.x }
              : { kty: 'EC', crv: 'P-256', x: wrapping.x, y: wrapping.y }),
          }
        : await newEncryptionKey();
      const wrappedKey = await wrap(pair.privateKey, proof.secret, result.principalId);
      if (!result.publicKey)
        await api(`/principals/${result.principalId}/encryption-key`, {
          method: 'PUT',
          body: { publicKey: pair.publicKey, wraps: { [result.credentialId]: wrappedKey } },
        });
      else
        await api(`/principals/${result.principalId}/credentials/${result.credentialId}/wrap`, {
          method: 'PUT',
          body: { wrappedKey, publicKey: result.publicKey },
        });
      await keep(result.principalId, pair.privateKey);
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
  const pair = secret
    ? existing
      ? { privateKey: existing, publicKey: principal!.publicKey! }
      : await newEncryptionKey()
    : null;
  const wrappedKey = secret && pair ? await wrap(pair.privateKey, secret, data.principalId) : undefined;
  const result = await api<Verified>('/auth/passkeys/verify', {
    method: 'POST',
    body: {
      challengeId: data.challengeId,
      credential: verificationCredential(credential),
      ...(pair ? { wrappedKey, ...(!principal?.publicKey ? { publicKey: pair.publicKey } : { existingPublicKey: pair.publicKey }) } : {}),
    },
  });
  if (pair) await keep(result.principalId, pair.privateKey);
  else if ((credential.clientExtensionResults as { prf?: { enabled?: boolean } }).prf?.enabled)
    return authenticate(result.principalId, credential.id, existing, false);
  return { ...result, encrypted: !!(await getKey(result.principalId)) };
}
export async function decryptSecret(id: string, principalId: string) {
  const key = await getKey(principalId);
  if (!key) throw new ApiFailure('key_locked');
  const content = await api<{ sealed: SealedContent; context: string }>(`/resources/${id}/secret`);
  try {
    return await open(content.sealed, key, principalId, content.context);
  } catch {
    await forget(principalId);
    throw new ApiFailure('key_unavailable');
  }
}

export async function migrateEncryptionKey(
  principalId: string,
  progress: (step: { name?: string; index: number; total: number; phase: 'passkey' | 'secrets' | 'saving' }) => void,
) {
  const pair = await newEncryptionKey();
  const path = `/principals/${principalId}/key-migration`;
  const plan = await api(path + '/options', { method: 'POST', body: { publicKey: pair.publicKey } }, KeyMigrationPlan);
  const credentials: KeyMigrationInput['credentials'] = [];
  let oldKey: JWK | undefined;
  const probe = await seal(encode('Foundation encryption key verification'), [{ id: principalId, publicKey: pair.publicKey }], 'key:' + principalId);
  for (const [index, item] of plan.credentials.entries()) {
    progress({ phase: 'passkey', name: item.name, index: index + 1, total: plan.credentials.length });
    const options = item.options as unknown as PublicKeyCredentialRequestOptionsJSON;
    const credential = await startAuthentication({ optionsJSON: {
      ...options, extensions: { ...options.extensions, prf: { eval: { first: seed, second: legacySeed } } },
    } });
    const secret = prf(credential), legacySecret = prf(credential, 'second');
    try {
      const previousSecret = item.wrappedKey.startsWith('x25519:') ? legacySecret : secret;
      if (!secret || !previousSecret) throw new ApiFailure('key_unsupported');
      const previous = await unwrap(item.wrappedKey, previousSecret, principalId, plan.publicKey)
        .catch(() => { throw new ApiFailure('key_unavailable'); });
      if (!matchesPublicKey(previous, plan.publicKey) || (oldKey && oldKey.d !== previous.d))
        throw new ApiFailure('key_unavailable');
      oldKey = previous;
      const wrappedKey = await wrap(pair.privateKey, secret, principalId);
      await open(probe, await unwrap(wrappedKey, secret, principalId, pair.publicKey), principalId, 'key:' + principalId);
      credentials.push({ id: item.id, credential: JSON.parse(JSON.stringify(verificationCredential(credential))), wrappedKey });
    } finally {
      secret?.fill(0);
      legacySecret?.fill(0);
    }
  }
  if (!oldKey) throw new ApiFailure('key_unavailable');
  const items: KeyMigrationInput['items'] = [];
  for (const [index, item] of plan.items.entries()) {
    progress({ phase: 'secrets', index: index + 1, total: plan.items.length });
    const context = 'resource:' + item.id;
    const content = await open(item.sealed, oldKey, principalId, context)
      .catch(() => { throw new ApiFailure('key_unavailable'); });
    try {
      const sealed = await seal(content, item.recipients.map(recipient => recipient.id === principalId
        ? { ...recipient, publicKey: pair.publicKey } : recipient), context);
      const verified = await open(sealed, pair.privateKey, principalId, context);
      try {
        if (content.length !== verified.length || !content.every((value, offset) => value === verified[offset]))
          throw new ApiFailure('key_unavailable');
      } finally { verified.fill(0); }
      if ('format' in sealed) throw new ApiFailure('invalid_envelope');
      items.push({ id: item.id, version: item.version, sealed });
    } finally { content.fill(0); }
  }
  progress({ phase: 'saving', index: 0, total: plan.items.length });
  await api(path, { method: 'POST', body: { challengeId: plan.challengeId, credentials, items } });
  await keep(principalId, pair.privateKey);
  return { secrets: items.length, passkeys: credentials.length };
}
export async function sealSecret(
  id: string,
  owner: string,
  content: Uint8Array,
  server: { id: string; publicKey: PublicEncryptionKey },
  allowUse: boolean,
  extra: string[] = [],
  existing = false,
) {
  const recipients = (
    await api<{ items: Array<{ id: string; publicKey: PublicEncryptionKey }> }>(
      existing ? `/resources/${id}/recipients` : `/principals/${owner}/recipients`,
    )
  ).items;
  for (const id of extra)
    if (id !== server.id && !recipients.some((value) => value.id === id)) {
      const recipient = await api<{ id: string; publicKey: PublicEncryptionKey | null }>(`/identities/${id}`);
      if (recipient.publicKey) recipients.push({ id, publicKey: recipient.publicKey });
    }
  if (allowUse) recipients.push(server);
  if (!recipients.length) throw new ApiFailure('key_locked');
  return seal(content, recipients, 'resource:' + id);
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
  const secret = result.wrappedKey?.startsWith('x25519:') ? proof.legacySecret : proof.secret;
  if (result.wrappedKey && secret)
    await keep(result.fromId, await unwrap(result.wrappedKey, secret, result.fromId, result.publicKey));
  return result;
}

export async function rekeySharing(path: string) {
  const plan = await api(path, {}, listOf(KeySharingItem));
  const updates: Record<string, { version: number; sealed: SealedContent }> = {};
  if (!plan.items.length) return updates;
  const principal = (await session()).principal;
  if (!principal) throw new ApiFailure('unauthenticated');
  let key = await getKey(principal.id);
  if (!key) {
    await authenticate(principal.id);
    key = await getKey(principal.id);
  }
  if (!key) throw new ApiFailure('key_locked');
  for (const item of plan.items) {
    let content: Uint8Array;
    try {
      content = await open(item.sealed, key, principal.id, 'resource:' + item.id);
    } catch {
      throw new ApiFailure('key_unavailable');
    }
    updates[item.id] = {
      version: item.version,
      sealed: await seal(content, item.recipients, 'resource:' + item.id),
    };
  }
  return updates;
}
