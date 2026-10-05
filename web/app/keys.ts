import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/browser';
import type { JWK } from 'jose';
import type { PrincipalView, PublicEncryptionKey, SealedContent } from '../../shared/contracts';
import { encode, hold, newEncryptionKey, open, seal, unwrap, wrap } from '../../shared/encryption';
import { api, ApiFailure } from './api';

const unlocked = new Map<string, JWK>();
const held = new Map<string, CryptoKey>();
const seed = encode('Foundation passkey encryption v1');
type Verified = { principalId: string; credentialId: string; wrappedKey: string | null; publicKey: PublicEncryptionKey | null; returnTo: string };
function database(): Promise<IDBDatabase> { return new Promise((resolve, reject) => { const request = indexedDB.open('foundation-keys', 1); request.onupgradeneeded = () => request.result.createObjectStore('keys'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); }); }
async function stored<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> { const db = await database(); try { return await new Promise<T>((resolve, reject) => { const transaction = db.transaction('keys', mode); const request = operation(transaction.objectStore('keys')); transaction.oncomplete = () => resolve(request.result); transaction.onerror = () => reject(transaction.error); transaction.onabort = () => reject(transaction.error); }); } finally { db.close(); } }
export async function getKey(id: string): Promise<CryptoKey | null> { return held.get(id) ?? (await stored('readonly', store => store.get(id)).catch(() => null) as CryptoKey | null); }
async function keep(id: string, key: JWK) { const cryptoKey = await hold(key); held.set(id, cryptoKey); unlocked.set(id, key); await stored('readwrite', store => store.put(cryptoKey, id)).catch(() => {}); }
export async function clearKeys() { unlocked.clear(); held.clear(); await stored('readwrite', store => store.clear()).catch(() => {}); }
function prf(credential: AuthenticationResponseJSON | RegistrationResponseJSON): Uint8Array | null { const output = credential.clientExtensionResults as { prf?: { results?: { first?: ArrayBuffer } } }; return output.prf?.results?.first ? new Uint8Array(output.prf.results.first) : null; }
function verificationCredential(credential: AuthenticationResponseJSON | RegistrationResponseJSON) { const { prf: _prf, ...extensions } = credential.clientExtensionResults as Record<string, unknown>; return { ...credential, clientExtensionResults: extensions }; }
async function assertion(principalId?: string, credentialId?: string) {
  const data = await api<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }>('/auth/passkeys/options', { method: 'POST', body: { intent: 'authenticate', ...(principalId ? { principalId } : {}) } });
  const options = { ...data.options, extensions: { ...data.options.extensions, prf: { eval: { first: seed } } }, ...(credentialId ? { allowCredentials: [{ id: credentialId, type: 'public-key' as const }] } : {}) };
  const credential = await startAuthentication({ optionsJSON: options });
  return { challengeId: data.challengeId, credential, secret: prf(credential) };
}
export async function authenticate(principalId?: string, credentialId?: string, wrapping?: JWK) {
  const proof = await assertion(principalId, credentialId);
  const result = await api<Verified>('/auth/passkeys/verify', { method: 'POST', body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) } });
  if (proof.secret) {
    if (result.wrappedKey) {
      const key = await unwrap(result.wrappedKey, proof.secret, result.principalId).catch(() => { throw new ApiFailure('key_unavailable'); });
      await keep(result.principalId, key);
    } else if (!result.publicKey || wrapping) {
      const pair = wrapping ? { privateKey: wrapping, publicKey: { kty: 'EC' as const, crv: 'P-256' as const, x: wrapping.x!, y: wrapping.y! } } : await newEncryptionKey();
      const wrappedKey = await wrap(pair.privateKey, proof.secret, result.principalId);
      if (!result.publicKey) await api(`/principals/${result.principalId}/encryption-key`, { method: 'PUT', body: { publicKey: pair.publicKey, wraps: { [result.credentialId]: wrappedKey } } });
      else await api(`/principals/${result.principalId}/credentials/${result.credentialId}/wrap`, { method: 'PUT', body: { wrappedKey } });
      await keep(result.principalId, pair.privateKey);
    }
  }
  return { ...result, encrypted: !!await getKey(result.principalId) };
}
export async function registerPasskey(name: string, principal?: Pick<PrincipalView, 'id' | 'publicKey'>) {
  let existing = principal ? unlocked.get(principal.id) : undefined;
  if (principal?.publicKey && !existing) { await authenticate(principal.id); existing = unlocked.get(principal.id); if (!existing) throw new ApiFailure('key_unavailable'); }
  const data = await api<{ challengeId: string; principalId: string; options: PublicKeyCredentialCreationOptionsJSON }>('/auth/passkeys/options', { method: 'POST', body: { intent: 'register', name, ...(principal ? { principalId: principal.id } : {}) } });
  const credential = await startRegistration({ optionsJSON: { ...data.options, extensions: { ...data.options.extensions, prf: { eval: { first: seed } } } } });
  const secret = prf(credential);
  const pair = secret ? existing ? { privateKey: existing, publicKey: principal!.publicKey! } : await newEncryptionKey() : null;
  const wrappedKey = secret && pair ? await wrap(pair.privateKey, secret, data.principalId) : undefined;
  const result = await api<Verified>('/auth/passkeys/verify', { method: 'POST', body: { challengeId: data.challengeId, credential: verificationCredential(credential), ...(pair ? { publicKey: pair.publicKey, wrappedKey } : {}) } });
  if (pair) await keep(result.principalId, pair.privateKey);
  else if ((credential.clientExtensionResults as { prf?: { enabled?: boolean } }).prf?.enabled) return authenticate(result.principalId, credential.id, existing);
  return { ...result, encrypted: !!await getKey(result.principalId) };
}
export async function decryptSecret(id: string, principalId: string) {
  const key = await getKey(principalId); if (!key) throw new ApiFailure('key_locked');
  const content = await api<{ sealed: SealedContent; context: string }>(`/resources/${id}/secret`);
  try { return await open(content.sealed, key, principalId, content.context); } catch { throw new ApiFailure('key_unavailable'); }
}
export async function sealSecret(id: string, owner: string, content: Uint8Array, server: { id: string; publicKey: PublicEncryptionKey }, allowUse: boolean, extra: string[] = [], existing = false) {
  const recipients = (await api<{ items: Array<{ id: string; publicKey: PublicEncryptionKey }> }>(existing ? `/resources/${id}/recipients` : `/principals/${owner}/recipients`)).items;
  for (const id of extra) if (id !== server.id && !recipients.some(value => value.id === id)) { const recipient = await api<{ id: string; publicKey: PublicEncryptionKey | null }>(`/identities/${id}`); if (recipient.publicKey) recipients.push({ id, publicKey: recipient.publicKey }); }
  if (allowUse) recipients.push(server);
  if (!recipients.length) throw new ApiFailure('key_locked');
  return seal(content, recipients, 'resource:' + id);
}
export async function mergeWithPasskey() {
  const proof = await assertion();
  const result = await api<{ id: string; fromId: string; wrappedKey: string | null }>('/account/merge/passkey', { method: 'POST', body: { challengeId: proof.challengeId, credential: verificationCredential(proof.credential) } });
  if (result.wrappedKey && proof.secret) await keep(result.fromId, await unwrap(result.wrappedKey, proof.secret, result.fromId));
  return result;
}
