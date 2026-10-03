import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { generateKey, open, seal, newContentKey, sealContent, openContent } from '../cli/envelope.mjs';

// Keys and envelopes: what lets a secret be opened, and by whom. A principal may publish one public key; its
// private key is its own, kept wrapped here per WebAuthn credential (so a credential's PRF unwraps it) or
// nowhere. A secret's key is kept once per recipient, sealed for their public key: an envelope. The server
// opens nothing with these. The one exception is Foundation's own principal, the agent: it has a key like any
// other, kept sealed here, and opens what was sealed for it when a owner has made it their agent - to inject
// into a command, to send a request. That key is the one thing the server can open with.
// What the server's own principal is called: it acts for those who make it their agent, and for nobody else.
const AGENT_NAME = 'Foundation Agent';
const KEY_LENGTH = 32;
const now = () => new Date().toISOString();

// Foundation's principal and key, made the first time they are needed. The private key is sealed with the
// database key, which is as far from the server as the enclave is not.
export function ensureAgent(db, vault) {
  const found = db.prepare("SELECT value FROM metadata WHERE name='agent_id'").get();
  if (found) {
    db.prepare('UPDATE principals SET name=? WHERE id=? AND name<>?').run(AGENT_NAME, found.value, AGENT_NAME);
    return found.value;
  }
  const id = randomUUID(), key = generateKey();
  db.prepare('INSERT INTO principals (id,name,created_at) VALUES (?,?,?)').run(id, AGENT_NAME, now());
  db.prepare('INSERT INTO principal_keys (principal_id,public_key,created_at) VALUES (?,?,?)').run(id, key.publicKey, now());
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('agent_id', id);
  db.prepare('INSERT INTO metadata VALUES (?,?)').run('agent_key', vault.seal(key.privateKey.toString('base64'), 'agent_key:' + id));
  return id;
}

export const bytes = (value, length) => {
  const decoded = typeof value === 'string' ? Buffer.from(value, 'base64url') : null;
  return decoded && (length === undefined ? decoded.length > 0 : decoded.length === length) ? decoded : null;
};
const text = buffer => Buffer.from(buffer).toString('base64url');

export class Keys {
  constructor(store) {
    Object.assign(this, { store, db: store.db, vault: store.vault });
    this.agentId = ensureAgent(this.db, this.vault);
  }
  // The agent's private key, read when needed and never kept on the object.
  agentKey() {
    const sealed = this.db.prepare("SELECT value FROM metadata WHERE name='agent_key'").get().value;
    return Buffer.from(this.vault.open(sealed, 'agent_key:' + this.agentId), 'base64');
  }

  publicKeyOf(principalId) {
    const row = this.db.prepare('SELECT public_key FROM principal_keys WHERE principal_id=?').get(principalId);
    return row ? Buffer.from(row.public_key) : null;
  }
  // A principal publishes its key once: envelopes made for it are made for that key.
  publish(principalId, publicKey) {
    const key = bytes(publicKey, KEY_LENGTH);
    if (!key) fail(400, 'invalid_key', '公開鍵を確認してください。');
    if (this.publicKeyOf(principalId)) fail(409, 'key_exists', 'この相手の鍵はすでにあります。');
    this.db.prepare('INSERT INTO principal_keys (principal_id,public_key,created_at) VALUES (?,?,?)').run(principalId, key, now());
  }
  // The private key wrapped for one credential, kept and given back as it came.
  keepWrap(credentialId, wrapped) {
    const value = bytes(wrapped);
    if (!value || value.length > 256) fail(400, 'invalid_wrap', '包んだ鍵を確認してください。');
    this.db.prepare('INSERT OR REPLACE INTO key_wraps (credential_id,wrapped) VALUES (?,?)').run(credentialId, value);
  }
  wrapOf(credentialId) {
    const row = credentialId ? this.db.prepare('SELECT wrapped FROM key_wraps WHERE credential_id=?').get(credentialId) : undefined;
    return row ? text(row.wrapped) : null;
  }
  // The principal's key as a client sees it: the public half, and - for its own - the private half wrapped per
  // credential, so that any of its credentials unwraps it.
  view(principalId, { own = false } = {}) {
    const key = this.publicKeyOf(principalId);
    const wraps = own ? Object.fromEntries(this.db.prepare('SELECT w.credential_id, w.wrapped FROM key_wraps w JOIN webauthn_credentials c ON c.id=w.credential_id WHERE c.principal_id=?').all(principalId).map(row => [row.credential_id, text(row.wrapped)])) : undefined;
    return { principal_id: principalId, public_key: key ? text(key) : null, ...(own ? { wraps } : {}) };
  }

  // Envelopes on one resource, by recipient. Given as the client made them; checked only for shape.
  envelopes(resourceId) {
    return this.db.prepare('SELECT principal_id, wrapped FROM envelopes WHERE resource_id=? ORDER BY principal_id').all(resourceId);
  }
  envelopeOf(resourceId, principalId) {
    const row = this.db.prepare('SELECT wrapped FROM envelopes WHERE resource_id=? AND principal_id=?').get(resourceId, principalId);
    return row ? Buffer.from(row.wrapped) : null;
  }
  recipientsOf(resourceId) { return this.envelopes(resourceId).map(row => row.principal_id); }
  // The recipients with their keys: whom a writer seals a new key for.
  recipientKeys(resourceId) {
    return this.recipientsOf(resourceId).map(id => ({ principal_id: id, public_key: this.publicKeyOf(id) })).filter(one => one.public_key).map(one => ({ ...one, public_key: one.public_key.toString('base64url') }));
  }
  envelopesOf(resourceId) { return Object.fromEntries(this.envelopes(resourceId).map(row => [row.principal_id, text(row.wrapped)])); }
  keepEnvelope(resourceId, principalId, wrapped) {
    const value = bytes(wrapped);
    if (!value || value.length > 256) fail(400, 'invalid_envelope', '封筒を確認してください。');
    if (!this.db.prepare('SELECT 1 FROM principals WHERE id=?').get(principalId)) fail(404, 'not_found', '相手が見つかりません。');
    this.db.prepare('INSERT OR REPLACE INTO envelopes (resource_id,principal_id,wrapped) VALUES (?,?,?)').run(resourceId, principalId, value);
  }
  // Each given envelope, as { principalId: wrapped }: an object of base64url strings, or nothing.
  keepEnvelopes(resourceId, envelopes) {
    if (envelopes === undefined) return;
    if (!envelopes || typeof envelopes !== 'object' || Array.isArray(envelopes)) fail(400, 'invalid_envelope', '封筒を確認してください。');
    for (const [principalId, wrapped] of Object.entries(envelopes)) this.keepEnvelope(resourceId, principalId, wrapped);
  }
  dropEnvelope(resourceId, principalId) {
    return this.db.prepare('DELETE FROM envelopes WHERE resource_id=? AND principal_id=?').run(resourceId, principalId).changes > 0;
  }

  // What the agent can do with what was sealed for it: open a secret's key, and so its bytes; seal a new secret
  // for whoever should have it; hand one it holds to another recipient.
  contentKeyFor(resourceId) {
    const envelope = this.envelopeOf(resourceId, this.agentId);
    if (!envelope) fail(409, 'not_sealed_for_foundation', 'このシークレットは Foundation に渡されていません。');
    return open(envelope, this.agentKey());
  }
  openFor(resourceId, sealed) { return openContent(this.contentKeyFor(resourceId), sealed); }
  sealFor(resourceId, content) { return sealContent(this.contentKeyFor(resourceId), content); }
  // Sealed by the agent for itself and for every recipient that has a key.
  sealAs(content, recipientIds) {
    const contentKey = newContentKey(), envelopes = {};
    for (const id of new Set([this.agentId, ...recipientIds])) {
      const key = this.publicKeyOf(id);
      if (key) envelopes[id] = text(seal(contentKey, key));
    }
    return { content: sealContent(contentKey, content), envelopes };
  }
  resealFor(resourceId, principalId) {
    const key = this.publicKeyOf(principalId);
    if (!key) fail(409, 'no_key', 'この相手はまだ鍵を持っていません。');
    this.keepEnvelope(resourceId, principalId, text(seal(this.contentKeyFor(resourceId), key)));
  }
}
