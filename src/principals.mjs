import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './crypto.mjs';
import { fail } from './errors.mjs';

// A principal is anything that comes to Foundation: a person, an AI, an app, an app's user. One row each,
// with a name and a beginning, and nothing that says which of those it is. What it may do follows from the
// lines between principals (relations) and from the credential it came in with.
export const KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const LINK = /^[A-Za-z0-9_-]{43}$/;
export const RELATIONS = ['owner', 'actor', 'viewer', 'editor'];
export const OBJECT_TYPES = ['principal', 'holding'];
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
        const found = this.db.prepare("SELECT object_id FROM relations WHERE subject_id=? AND relation='owner' AND object_type='principal' AND alias=?").get(ownerId, alias);
        if (found) return this.get(found.object_id);
      }
      if (this.db.prepare("SELECT count(*) n FROM relations WHERE subject_id=? AND relation='owner' AND object_type='principal'").get(ownerId).n >= OWNED_MAX) fail(409, 'principal_limit', '作れる相手の上限に達しました。');
      const id = randomUUID(), at = now();
      this.db.prepare('INSERT INTO principals (id,name,created_at) VALUES (?,?,?)').run(id, name, at);
      this.relate(ownerId, 'owner', 'principal', id, { alias });
      return this.get(id);
    });
  }
  rename(id, name) {
    if (!this.db.prepare('UPDATE principals SET name=? WHERE id=?').run(name, id).changes) fail(404, 'not_found', '相手が見つかりません。');
    return this.get(id);
  }
  // Removing a principal takes its credentials and lines (by cascade) and its sessions. What it holds is the
  // holdings' business, cleared by the caller first; the principals it made stay, as their own; the requests it was
  // part of stay, as records.
  remove(id) {
    return this.store.transaction(() => {
      this.db.prepare('DELETE FROM sessions WHERE owner_id=?').run(id);
      this.db.prepare('DELETE FROM relations WHERE object_type=? AND object_id=?').run('principal', id);
      return this.db.prepare('DELETE FROM principals WHERE id=?').run(id).changes > 0;
    });
  }

  // Lines between principals, and from principals onto what is held. A held thing is pointed at by its id.
  relate(subjectId, relation, objectType, objectId, { alias, scope } = {}) {
    if (!RELATIONS.includes(relation) || !OBJECT_TYPES.includes(objectType)) fail(400, 'invalid_relation', '関係の種類を確認してください。');
    if (objectType === 'principal' && !this.get(objectId)) fail(404, 'not_found', '相手が見つかりません。');
    if (subjectId === objectId && objectType === 'principal') fail(400, 'invalid_relation', '自分自身との関係は引けません。');
    this.db.prepare('INSERT OR REPLACE INTO relations (subject_id,relation,object_type,object_id,alias,scope,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(subjectId, relation, objectType, objectId, alias ?? null, scope ?? null, now());
  }
  unrelate(subjectId, relation, objectType, objectId) {
    return this.db.prepare('DELETE FROM relations WHERE subject_id=? AND relation=? AND object_type=? AND object_id=?').run(subjectId, relation, objectType, objectId).changes > 0;
  }
  has(subjectId, relation, objectType, objectId) {
    return this.db.prepare('SELECT scope FROM relations WHERE subject_id=? AND relation=? AND object_type=? AND object_id=?').get(subjectId, relation, objectType, objectId);
  }
  // Every line a principal is on, either end.
  relationsOf(id) {
    return this.db.prepare('SELECT subject_id,relation,object_type,object_id,alias,scope,created_at FROM relations WHERE subject_id=? OR (object_type=? AND object_id=?) ORDER BY created_at').all(id, 'principal', id);
  }
  // Lines onto one held thing: who may see or change it.
  linesOnto(holdingId) {
    return this.db.prepare("SELECT subject_id,relation,created_at FROM relations WHERE object_type='holding' AND object_id=? ORDER BY created_at").all(holdingId);
  }
  // What is held by others and shown to this principal, with the line it is shown along.
  shownTo(id) {
    return this.db.prepare(`SELECT h.id, h.holder_id, h.kind, h.name, COALESCE(o.size, g.size) AS size, o.type, h.updated_at, r.relation FROM relations r JOIN holdings h ON h.id=r.object_id
      LEFT JOIN objects o ON o.holding_id=h.id LEFT JOIN grants g ON g.holding_id=h.id
      WHERE r.subject_id=? AND r.object_type='holding' ORDER BY r.created_at`).all(id);
  }
  ownersOf(id) { return this.db.prepare("SELECT subject_id AS id FROM relations WHERE relation='owner' AND object_type='principal' AND object_id=?").all(id).map(row => row.id); }
  // The principals this one owns, each with the name it gave them and the credentials they carry.
  owned(ownerId) {
    return this.db.prepare(`SELECT p.id, p.name, p.created_at, r.alias FROM relations r JOIN principals p ON p.id=r.object_id
      WHERE r.subject_id=? AND r.relation='owner' AND r.object_type='principal' ORDER BY r.created_at, p.id`).all(ownerId)
      .map(row => ({ ...row, credentials: this.credentials(row.id), acts_for: this.actsFor(row.id) }));
  }
  ownedByAlias(ownerId, alias) {
    const found = this.db.prepare("SELECT object_id FROM relations WHERE subject_id=? AND relation='owner' AND object_type='principal' AND alias=?").get(ownerId, alias);
    return found ? this.get(found.object_id) : undefined;
  }
  // Whom this principal acts for, and who acts for it.
  actsFor(id) { return this.db.prepare("SELECT object_id AS id, scope FROM relations WHERE subject_id=? AND relation='actor' AND object_type='principal'").all(id); }
  actorsOf(id) {
    return this.db.prepare(`SELECT p.id, p.name, p.created_at, r.scope FROM relations r JOIN principals p ON p.id=r.subject_id
      WHERE r.relation='actor' AND r.object_type='principal' AND r.object_id=? ORDER BY r.created_at`).all(id).map(row => ({ ...row, credentials: this.credentials(row.id) }));
  }

  // Credentials: how a principal proves it is itself. A key is long-lived and reaches everything the principal
  // may reach; a link is short-lived and reaches one request. The secret is never stored, only its hash.
  credentials(principalId) {
    return this.db.prepare('SELECT id,kind,scope,expires_at,created_at,last_used_at FROM credentials WHERE principal_id=? AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at,id').all(principalId, Date.now());
  }
  issue(principalId, { kind = 'key', scope = null, expiresIn = null, token } = {}) {
    if (!['key', 'link'].includes(kind)) fail(400, 'invalid_credential', '資格情報の種類を確認してください。');
    const secret = token ?? (kind === 'key' ? 'fdn_' + randomBytes(32).toString('base64url') : randomBytes(32).toString('base64url'));
    if (!(kind === 'key' ? KEY : LINK).test(secret)) fail(400, 'invalid_token', '資格情報の形式が無効です。');
    if (kind === 'key' && this.credentials(principalId).filter(row => row.kind === 'key').length >= KEYS_MAX) fail(409, 'key_limit', `登録できるキーは${KEYS_MAX}件までです。`);
    const id = randomUUID(), at = now();
    this.db.prepare('INSERT INTO credentials (id,hash,principal_id,kind,scope,expires_at,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(id, digest(secret), principalId, kind, scope, expiresIn === null ? null : Date.now() + expiresIn, at);
    return { id, kind, scope, expires_at: expiresIn === null ? null : Date.now() + expiresIn, created_at: at, token: secret };
  }
  revoke(principalId, credentialId) {
    return this.db.prepare('DELETE FROM credentials WHERE principal_id=? AND id=?').run(principalId, credentialId).changes > 0;
  }
  byHash(hash) {
    return this.db.prepare('SELECT c.id,c.kind,c.scope,c.expires_at,c.principal_id FROM credentials c WHERE c.hash=? AND (c.expires_at IS NULL OR c.expires_at>?)').get(hash, Date.now());
  }
  // Who a token speaks for. Nothing is said about what they may do.
  authenticate(token) {
    if (typeof token !== 'string' || !(KEY.test(token) || LINK.test(token))) return;
    const credential = this.byHash(digest(token));
    if (!credential) return;
    this.db.prepare('UPDATE credentials SET last_used_at=? WHERE id=?').run(now(), credential.id);
    return { principal: this.get(credential.principal_id), credential: { id: credential.id, kind: credential.kind, scope: credential.scope } };
  }
  // Spending a link: the one in the URL is gone, and a short one for the browser takes its place.
  exchange(token) {
    return this.store.transaction(() => {
      const found = this.byHash(digest(String(token ?? '')));
      if (!found || found.kind !== 'link') fail(410, 'link_expired', 'このリンクは使えません。元の画面から開き直してください。');
      this.db.prepare('DELETE FROM credentials WHERE id=?').run(found.id);
      return { principal_id: found.principal_id, scope: found.scope, ...this.issue(found.principal_id, { kind: 'link', scope: found.scope, expiresIn: 30 * 60_000 }) };
    });
  }
  sweep() { this.db.prepare('DELETE FROM credentials WHERE expires_at IS NOT NULL AND expires_at<=?').run(Date.now()); }
}
