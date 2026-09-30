import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './crypto.mjs';
import { fail } from './errors.mjs';
import { ROLES, ACTION } from './authorization.mjs';

// A principal is anything that comes to Foundation: a person, an AI, an app, an app's user. One row each,
// with a name and a beginning, and nothing that says which of those it is. What it may do follows from the
// lines between principals (relations) and from the access key it came in with.
export const KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const LINK = /^[A-Za-z0-9_-]{43}$/;
export const OBJECT_TYPES = ['principal', 'resource'];
const OWNED_MAX = 100_000, KEYS_MAX = 50;
const now = () => new Date().toISOString();

export class Principals {
  constructor(store) { this.store = store; this.db = store.db; }

  get(id) { return typeof id === 'string' ? this.db.prepare('SELECT id,name,created_at FROM principals WHERE id=?').get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', '相手が見つかりません。');
    return row;
  }
  // A principal exists from the first time it is seen: a person by the id their login gave them, anyone else
  // because someone made it. The maker owns it and may call it by a name of their own (alias).
  ensure(id, name = '') {
    this.db.prepare('INSERT OR IGNORE INTO principals (id,name,created_at) VALUES (?,?,?)').run(id, name, now());
    return this.get(id);
  }
  create(ownerId, { name = '', alias } = {}) {
    return this.store.transaction(() => {
      if (alias !== undefined) {
        const found = this.ownedByAlias(ownerId, alias);
        if (found) return found;
      }
      if (this.db.prepare("SELECT count(*) n FROM relations WHERE subject_id=? AND relation='owner' AND object_type='principal'").get(ownerId).n >= OWNED_MAX) fail(409, 'principal_limit', '作れる相手の上限に達しました。');
      const id = randomUUID(), at = now();
      this.db.prepare('INSERT INTO principals (id,name,created_at) VALUES (?,?,?)').run(id, name, at);
      this.relate(ownerId, 'owner', 'principal', id);
      if (alias !== undefined) this.db.prepare('INSERT INTO aliases (owner_id,principal_id,alias) VALUES (?,?,?)').run(ownerId, id, alias);
      return this.get(id);
    });
  }
  rename(id, name) {
    if (!this.db.prepare('UPDATE principals SET name=? WHERE id=?').run(name, id).changes) fail(404, 'not_found', '相手が見つかりません。');
    return this.get(id);
  }
  // Removing a principal takes its access keys and lines (by cascade) and its sessions. What it holds is the
  // resources' business, cleared by the caller first; the principals it made stay, as their own; the requests it was
  // part of stay, as records.
  remove(id) {
    return this.store.transaction(() => {
      this.db.prepare('DELETE FROM sessions WHERE owner_id=?').run(id);
      this.db.prepare('DELETE FROM relations WHERE object_type=? AND object_id=?').run('principal', id);
      return this.db.prepare('DELETE FROM principals WHERE id=?').run(id).changes > 0;
    });
  }

  // Lines between principals, and from principals onto resources. A resource is pointed at by its id.
  relate(subjectId, relation, objectType, objectId) {
    if (!(ROLES.includes(relation) || ACTION.test(relation)) || !OBJECT_TYPES.includes(objectType)) fail(400, 'invalid_relation', '関係の種類を確認してください。');
    if (!this.get(subjectId) || (objectType === 'principal' && !this.get(objectId))) fail(404, 'not_found', '相手が見つかりません。');
    if (subjectId === objectId && objectType === 'principal') fail(400, 'invalid_relation', '自分自身との関係は引けません。');
    this.db.prepare('INSERT OR IGNORE INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,?,?,?,?)')
      .run(subjectId, relation, objectType, objectId, now());
  }
  unrelate(subjectId, relation, objectType, objectId) {
    return this.db.prepare('DELETE FROM relations WHERE subject_id=? AND relation=? AND object_type=? AND object_id=?').run(subjectId, relation, objectType, objectId).changes > 0;
  }
  // Stop this principal's access to one holder: every line onto the holder, but the holder's ownership of it, and
  // onto what the holder has. Its identity and keys remain.
  revokeAccess(subjectId, holderId) {
    return this.db.prepare(`DELETE FROM relations WHERE subject_id=? AND relation<>'owner' AND (
      (object_type='principal' AND object_id=?) OR (object_type='resource' AND object_id IN (SELECT id FROM resources WHERE holder_id=?)))`)
      .run(subjectId, holderId, holderId).changes;
  }
  has(subjectId, relation, objectType, objectId) {
    return Boolean(this.db.prepare('SELECT 1 FROM relations WHERE subject_id=? AND relation=? AND object_type=? AND object_id=?').get(subjectId, relation, objectType, objectId));
  }
  // Every line a principal is on, either end.
  relationsOf(id) {
    return this.db.prepare('SELECT subject_id,relation,object_type,object_id,created_at FROM relations WHERE subject_id=? OR (object_type=? AND object_id=?) ORDER BY created_at').all(id, 'principal', id);
  }
  // Lines onto one resource: who may see or change it.
  linesOnto(resourceId) {
    return this.db.prepare("SELECT subject_id,relation,created_at FROM relations WHERE object_type='resource' AND object_id=? ORDER BY created_at").all(resourceId);
  }
  // What others hold and show to this principal, with the line it is shown along.
  shownTo(id) {
    return this.db.prepare(`SELECT x.id, x.holder_id, x.kind, x.name, COALESCE(o.size, s.size) AS size, o.type, x.updated_at, l.relation FROM relations l JOIN resources x ON x.id=l.object_id
      LEFT JOIN objects o ON o.resource_id=x.id LEFT JOIN secrets s ON s.resource_id=x.id
      WHERE l.subject_id=? AND l.object_type='resource' ORDER BY l.created_at`).all(id);
  }
  ownersOf(id) { return this.db.prepare("SELECT subject_id AS id FROM relations WHERE relation='owner' AND object_type='principal' AND object_id=?").all(id).map(row => row.id); }
  // The principals this one owns, each with the name it gave them and the access keys they carry.
  owned(ownerId) {
    return this.db.prepare(`SELECT p.id, p.name, p.created_at, a.alias FROM relations r JOIN principals p ON p.id=r.object_id
      LEFT JOIN aliases a ON a.owner_id=r.subject_id AND a.principal_id=r.object_id
      WHERE r.subject_id=? AND r.relation='owner' AND r.object_type='principal' ORDER BY r.created_at, p.id`).all(ownerId)
      .map(row => ({ ...row, keys: this.keys(row.id), acts_for: this.actsFor(row.id) }));
  }
  // The name an owner calls what it owns by: the owner's record, not a line.
  ownedByAlias(ownerId, alias) {
    const found = this.db.prepare('SELECT principal_id FROM aliases WHERE owner_id=? AND alias=?').get(ownerId, alias);
    return found ? this.get(found.principal_id) : undefined;
  }
  aliasOf(ownerId, principalId) { return this.db.prepare('SELECT alias FROM aliases WHERE owner_id=? AND principal_id=?').get(ownerId, principalId)?.alias ?? null; }
  // Whom this principal acts for, and who acts for it.
  actsFor(id) { return this.db.prepare("SELECT object_id AS id FROM relations WHERE subject_id=? AND relation='actor' AND object_type='principal'").all(id).map(row => row.id); }
  actorsOf(id) {
    return this.db.prepare(`SELECT p.id, p.name, p.created_at, r.created_at AS approved_at FROM relations r JOIN principals p ON p.id=r.subject_id
      WHERE r.relation='actor' AND r.object_type='principal' AND r.object_id=? ORDER BY r.created_at`).all(id).map(row => ({ ...row, keys: this.keys(row.id) }));
  }

  // Access keys: what a machine (an AI, an app, a lent environment) shows to be a principal. Reaches whatever the
  // principal may reach. A key made for an environment names it and lives no longer than it. Only a hash is kept.
  keys(principalId) {
    return this.db.prepare('SELECT id,created_at,last_used_at,expires_at,environment_id FROM access_keys WHERE principal_id=? AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at,id')
      .all(principalId, Date.now()).map(({ expires_at, environment_id, ...row }) => ({ ...row, ...(environment_id ? { expires_at, environment_id } : {}) }));
  }
  hasKey(principalId, keyId) { return Boolean(this.db.prepare('SELECT 1 FROM access_keys WHERE principal_id=? AND id=? AND (expires_at IS NULL OR expires_at>?)').get(principalId, keyId, Date.now())); }
  issueKey(principalId, { expiresAt = null, environmentId = null } = {}) {
    if (!environmentId && this.keys(principalId).filter(row => !row.environment_id).length >= KEYS_MAX) fail(409, 'key_limit', `登録できるキーは${KEYS_MAX}件までです。`);
    const token = 'fdn_' + randomBytes(32).toString('base64url'), id = randomUUID(), at = now();
    this.db.prepare('INSERT INTO access_keys (id,hash,principal_id,created_at,expires_at,environment_id) VALUES (?,?,?,?,?,?)').run(id, digest(token), principalId, at, expiresAt, environmentId);
    return { id, created_at: at, token };
  }
  // The keys an environment was given go with it.
  revokeEnvironmentKeys(environmentId) { return this.db.prepare('DELETE FROM access_keys WHERE environment_id=?').run(environmentId).changes; }
  revokeKey(principalId, keyId) {
    return this.db.prepare('DELETE FROM access_keys WHERE principal_id=? AND id=?').run(principalId, keyId).changes > 0;
  }
  // Who a key speaks for. Nothing is said about what they may do.
  authenticateKey(token) {
    if (typeof token !== 'string' || !KEY.test(token)) return;
    const row = this.db.prepare('SELECT id,principal_id,environment_id FROM access_keys WHERE hash=? AND (expires_at IS NULL OR expires_at>?)').get(digest(token), Date.now());
    if (!row) return;
    this.db.prepare('UPDATE access_keys SET last_used_at=? WHERE id=?').run(now(), row.id);
    return { principal: this.get(row.principal_id), key: { id: row.id, ...(row.environment_id ? { environment: row.environment_id } : {}) } };
  }

  // Request links: what a person is handed to answer one request without logging in. Short-lived, spent when
  // opened, and good for that one request only. Only a hash of it is kept.
  issueLink(principalId, requestId, ttl) {
    const token = randomBytes(32).toString('base64url'), id = randomUUID(), at = now(), expiresAt = Date.now() + ttl;
    this.db.prepare('INSERT INTO request_links (id,hash,principal_id,request_id,expires_at,created_at) VALUES (?,?,?,?,?,?)').run(id, digest(token), principalId, requestId, expiresAt, at);
    return { id, request_id: requestId, expires_at: expiresAt, token };
  }
  findLink(token, requestId) {
    if (typeof token !== 'string' || !LINK.test(token) || typeof requestId !== 'string') return;
    return this.db.prepare('SELECT id,principal_id,request_id FROM request_links WHERE hash=? AND request_id=? AND expires_at>?').get(digest(token), requestId, Date.now());
  }
  hasLink(principalId, linkId) { return Boolean(this.db.prepare('SELECT 1 FROM request_links WHERE principal_id=? AND id=? AND expires_at>?').get(principalId, linkId, Date.now())); }
  // Who a link speaks for, and the one request it reaches.
  authenticateLink(token, requestId) {
    const row = this.findLink(token, requestId);
    return row ? { principal: this.get(row.principal_id), link: { id: row.id, request: row.request_id } } : undefined;
  }
  // Opening a link spends it: the one in the URL is gone, and a short one for the browser takes its place.
  exchangeLink(token, requestId, ttl) {
    return this.store.transaction(() => {
      const found = this.findLink(token, requestId);
      if (!found) fail(410, 'link_expired', 'このリンクは使えません。元の画面から開き直してください。');
      this.db.prepare('DELETE FROM request_links WHERE id=?').run(found.id);
      return { principal_id: found.principal_id, ...this.issueLink(found.principal_id, found.request_id, ttl) };
    });
  }
  sweep(now = Date.now()) {
    this.db.prepare('DELETE FROM request_links WHERE expires_at<=?').run(now);
    this.db.prepare('DELETE FROM access_keys WHERE expires_at IS NOT NULL AND expires_at<=?').run(now);
    this.sweepAbandoned(now);
  }
  // A principal anyone made for themselves and then left: it carries a key nobody has used for a day, nobody took it
  // on, it holds and has set up nothing, it waits on no request, and no one is logged in as it. It is gone, keys and all.
  sweepAbandoned(now = Date.now()) {
    const cutoff = new Date(now - 86_400_000).toISOString();
    return this.db.prepare(`DELETE FROM principals WHERE created_at<?
      AND EXISTS (SELECT 1 FROM access_keys k WHERE k.principal_id=principals.id)
      AND NOT EXISTS (SELECT 1 FROM access_keys k WHERE k.principal_id=principals.id AND k.last_used_at>=?)
      AND NOT EXISTS (SELECT 1 FROM relations r WHERE r.subject_id=principals.id OR (r.object_type='principal' AND r.object_id=principals.id))
      AND NOT EXISTS (SELECT 1 FROM resources h WHERE h.holder_id=principals.id)
      AND NOT EXISTS (SELECT 1 FROM settings s WHERE s.principal_id=principals.id)
      AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.owner_id=principals.id)
      AND NOT EXISTS (SELECT 1 FROM requests q WHERE q.from_id=principals.id AND q.status='pending' AND q.expires_at>?)`).run(cutoff, cutoff, now).changes;
  }
}
