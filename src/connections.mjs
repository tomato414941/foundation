import { fail, HttpError } from './errors.mjs';
import { scopeFacts } from './scopes.mjs';
import { FOUNDATION_APP, takesApps } from './apps.mjs';
import { randomUUID } from 'node:crypto';

// What a principal holds for a service, by one of its schemes: OAuth renewal state, the role short-lived keys are
// obtained with, or a token the owner pasted. Arbitrary private bytes are secrets (secrets.mjs); nothing moves one
// into the other.
export const CONNECTION_LIMIT = 50;
const COLUMNS = 'r.id,r.owner_id,r.kind,r.name,r.created_at,r.updated_at,c.service,c.auth_scheme,c.app_id,c.subject,c.status,c.generation';
const FROM = 'FROM resources r JOIN connections c ON c.resource_id=r.id';
const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');

export class Connections {
  // services: where a connection works (services.mjs); apps: the OAuth apps connections are made through (apps.mjs).
  constructor(store, resources, services, apps) {
    Object.assign(this, { store, db: store.db, vault: store.vault, resources, services, apps, pending: new Map() });
  }
  // The scheme as it speaks for this connection: through the app it was made with, for OAuth.
  schemeFor(row) { return row.auth_scheme === 'oauth' ? this.apps.scheme(row.service, row.app_id) : this.services.scheme(row.service, row.auth_scheme); }
  binding(row) { return `connection:${row.owner_id}:${row.id}`; }

  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  held(ownerId, id) { const row = this.get(id); return row && row.owner_id === ownerId ? row : undefined; }
  list(ownerId, { service, prefix } = {}) {
    const where = ['r.owner_id=?'], params = [ownerId];
    if (service !== undefined) { where.push('c.service=?'); params.push(service); }
    if (prefix !== undefined) { where.push('substr(r.name,1,length(?))=? COLLATE BINARY'); params.push(String(prefix), String(prefix)); }
    return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE ${where.join(' AND ')} ORDER BY r.name,r.created_at,r.id`).all(...params);
  }
  rename(row, name) { return this.get(this.resources.rename(row, String(name ?? '').slice(0, 80) || row.name).id); }
  remove(row) { this.resources.remove(row); }

  // For a service: what its scheme left with Foundation, and what it says about the account.
  state(row) { return this.vault.open(this.db.prepare('SELECT state FROM connections WHERE resource_id=?').get(row.id).state, this.binding(row)); }
  context(row) { return row ? { subject: row.subject, privateState: this.state(row).private_state } : undefined; }
  // requested: the scopes this connection asked the service for (null for a scheme without scopes).
  nextState(result, { requested } = {}) {
    if (!result || (result.subject !== null && (typeof result.subject !== 'string' || !result.subject || result.subject.length > 512))
      || !Object.hasOwn(result, 'privateState') || result.privateState === undefined
      || !result.facts || typeof result.facts !== 'object' || Array.isArray(result.facts)
      || (result.expiresAt !== null && !(Number.isFinite(result.expiresAt) && result.expiresAt > Date.now()))) invalidResult();
    return { private_state: result.privateState, facts: result.facts, expires_at: result.expiresAt, ...(requested ? { requested_scopes: requested } : {}) };
  }
  forService(ownerId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_connection', '接続のIDを指定してください。');
    const row = this.held(ownerId, id);
    if (!row) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  // The connection a new authorization replaces: the same service and scheme, still there, and one that can be.
  reconnection(ownerId, serviceRef, schemeId, id) {
    const row = this.forService(ownerId, id);
    if (row.service !== serviceRef || row.auth_scheme !== schemeId) fail(400, 'invalid_service', 'サービスか接続の方法が一致しません。');
    if (this.services.scheme(serviceRef, schemeId).canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
    if (row.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
    return row;
  }
  // app: the app it was made through - a held app's id, or Foundation's - for a scheme authorized through apps;
  // none otherwise. name: what the owner calls a pasted token; the service cannot say whose it is.
  save(ownerId, serviceRef, schemeId, result, { previous, scopes, app = FOUNDATION_APP, name } = {}) {
    const scheme = this.services.scheme(serviceRef, schemeId);
    const state = this.nextState(result, { requested: scopes });
    const said = scheme.kind === 'token' ? name ?? (previous ? null : this.services.summary(serviceRef).name + 'のトークン') : state.facts.label || result.subject;
    const label = said === null ? null : String(said).slice(0, 80) || this.services.summary(serviceRef).name;
    return this.keep(ownerId, { service: serviceRef, scheme: schemeId, app: takesApps(scheme) ? app : null, subject: result.subject, label, state }, previous);
  }
  // Identity and renewal state belong to the connection, independently of requests. previous is the managed
  // authorization being connected again.
  keep(ownerId, { service, scheme, app = null, subject, label, state }, previous) {
    return this.store.transaction(() => {
      const existing = previous ? this.held(ownerId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        this.reconnection(ownerId, service, scheme, existing.id);
      }
      if (!previous && this.list(ownerId).length >= CONNECTION_LIMIT) fail(409, 'connection_limit', `登録できる接続は${CONNECTION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID(), sealed = this.vault.seal(state, `connection:${ownerId}:${id}`);
      if (existing) {
        this.db.prepare("UPDATE connections SET service=?,auth_scheme=?,app_id=?,subject=?,state=?,status='usable',generation=generation+1 WHERE resource_id=?").run(service, scheme, app, subject, sealed, id);
        if (label !== null) this.resources.rename(existing, label);
      } else {
        this.resources.insert(id, ownerId, 'connection', label);
        this.db.prepare("INSERT INTO connections (resource_id,service,auth_scheme,app_id,subject,status,state) VALUES (?,?,?,?,?,'usable',?)").run(id, service, scheme, app, subject, sealed);
      }
      return this.get(id);
    });
  }
  saveState(row, state, subject = row.subject) {
    return this.store.transaction(() => {
      this.current(row);
      this.db.prepare('UPDATE connections SET subject=?,state=? WHERE resource_id=?').run(subject, this.vault.seal(state, this.binding(row)), row.id);
      this.resources.touch(row.id);
    });
  }
  reconnectRequired(row) {
    this.db.prepare("UPDATE connections SET status='reconnect_required',generation=generation+1 WHERE resource_id=? AND generation=? AND status='usable'").run(row.id, row.generation);
    this.resources.touch(row.id);
  }
  disconnect(ownerId, id) {
    return this.store.transaction(() => {
      const row = this.forService(ownerId, id);
      this.db.prepare("UPDATE connections SET status='disconnecting',generation=generation+1 WHERE resource_id=?").run(row.id);
      this.resources.touch(row.id);
      return row;
    });
  }
  current(row) {
    const current = this.held(row.owner_id, row.id);
    if (!current || current.generation !== row.generation) fail(409, 'connection_changed', '接続の状態が変わりました。');
    if (current.status !== 'usable') fail(409, 'reconnect_required', 'この接続は利用できません。接続し直してください。');
    return current;
  }
  outputs(scheme, produced) {
    if (!produced || typeof produced !== 'object') invalidResult();
    const values = new Map();
    const add = (key, content, filename) => {
      if (!scheme.variables.includes(key) || values.has(key)) invalidResult();
      if (content.length > 64 * 1024) fail(502, 'service_response', '受け取った内容が大きすぎます。');
      values.set(key, { content, ...(filename ? { filename } : {}) });
    };
    for (const [key, value] of Object.entries(produced.environment || {})) {
      if (typeof value !== 'string') invalidResult();
      add(key, Buffer.from(value, 'utf8'));
    }
    for (const file of produced.files || []) add(file.env, Buffer.from(file.content, 'utf8'), file.filename);
    return values;
  }
  // One connection operation per generation, including persistence. This also preserves rotated private state when
  // a caller's authorization or snapshot save fails.
  async obtain(row) {
    const current = this.current(row), key = current.id + ':' + current.generation;
    if (!this.pending.has(key)) {
      const pending = this.obtainCurrent(current);
      this.pending.set(key, pending);
      pending.finally(() => { if (this.pending.get(key) === pending) this.pending.delete(key); }).catch(() => {});
    }
    const result = await this.pending.get(key);
    this.current(row);
    return result;
  }
  async obtainCurrent(row) {
    try {
      // Read before asking the service: the connection may be removed while the service answers.
      const requested = this.state(row).requested_scopes, active = this.schemeFor(row);
      const result = await active.obtain(this.context(row));
      const state = this.nextState(result, { requested });
      this.saveState(row, state, result.subject);
      return { state, values: this.outputs(active, result.credentials) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed', 'refresh_missing'].includes(error.code)) this.reconnectRequired(row);
      throw error;
    }
  }

  // What this managed authorization yields right now.
  // Values are a Map of variable name to {content, filename?}.
  async derive(row) {
    const result = await this.obtain(row);
    return { values: result.values, expires_at: result.state.expires_at, facts: { ...result.state.facts, ...scopeFacts(result.state) } };
  }
  // What is said of a connection. The owner sees everything but the sealed state; whoever acts for them sees what
  // they need to use it. Whether disconnecting can also take it back at the service is as the app it was made
  // through can.
  // What the owner pasted, for a token; what renews the others is Foundation's to keep and of no use elsewhere.
  handed(row) {
    if (row.auth_scheme !== 'token') return undefined;
    return this.state(row).private_state.fields;
  }
  revocable(row) {
    try { return typeof this.schemeFor(row).revoke === 'function'; } catch { return false; }
  }
  view(row, { owner = false } = {}) {
    const base = { ...this.resources.view(row), service: this.services.summary(row.service), auth_scheme: row.auth_scheme, status: row.status };
    const state = this.state(row);
    let scheme = null;
    try { scheme = this.services.scheme(row.service, row.auth_scheme); } catch {}
    const shared = { label: state.facts.label || row.name, facts: { ...state.facts, ...scopeFacts(state) }, ...(scheme && takesApps(scheme) ? { app: this.apps.reference(row.app_id) } : {}),
      variables: scheme?.variables ?? [] };
    if (!owner) return { ...base, ...shared };
    return { ...base, ...shared, subject: row.subject, generation: row.generation, expires_at: state.expires_at,
      can_reconnect: Boolean(scheme) && scheme.canReconnect !== false, can_revoke: this.revocable(row), available: Boolean(scheme?.available) };
  }
}
