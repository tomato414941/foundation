import { fail, HttpError } from './errors.mjs';
import { VALUE_MAX } from './secrets.mjs';
import { randomUUID } from 'node:crypto';

const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');
export const CONNECTION_LIMIT = 50;
const now = () => new Date().toISOString();

export class Connections {
  constructor(store, connectors) { this.store = store; this.db = store.db; this.vault = store.vault; this.connectors = connectors; this.pending = new Map(); }
  list(ownerId) { return this.db.prepare('SELECT * FROM connections WHERE owner_id=? ORDER BY created_at,id').all(ownerId); }
  get(ownerId, id) { return this.db.prepare('SELECT * FROM connections WHERE owner_id=? AND id=?').get(ownerId, id); }
  at(ownerId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_connection', '接続IDを指定してください。');
    const row = this.get(ownerId, id);
    if (!row) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  state(row) { return this.vault.open(row.state, `connection:${row.owner_id}:${row.id}`); }
  context(row) { return row ? { subject: row.subject, privateState: this.state(row).private_state } : undefined; }
  nextState(result) {
    if (!result || typeof result.subject !== 'string' || !result.subject || result.subject.length > 512
      || !Object.hasOwn(result, 'privateState') || result.privateState === undefined
      || !result.facts || typeof result.facts !== 'object' || Array.isArray(result.facts)
      || (result.expiresAt !== null && !(Number.isFinite(result.expiresAt) && result.expiresAt > Date.now()))) invalidResult();
    return { private_state: result.privateState, facts: result.facts, expires_at: result.expiresAt };
  }
  save(ownerId, connectorId, result, { keptBy = '', previous } = {}) {
    this.connectors.get(connectorId);
    const state = this.nextState(result);
    if (previous && result.subject !== previous.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
    const label = String(state.facts.label || result.subject).slice(0, 80);
    return this.write(ownerId, { connector: connectorId, subject: result.subject, label, keptBy, state }, previous);
  }
  // Identity and renewal state belong to the connection, independently of saved values or requests.
  write(ownerId, { connector, subject, label, state, keptBy = '' }, previous) {
    return this.store.transaction(() => {
      const stamp = now(), existing = previous ? this.get(ownerId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        if (existing.subject !== subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
      }
      if (!previous && this.db.prepare('SELECT 1 FROM connections WHERE owner_id=? AND connector=? AND subject=?').get(ownerId, connector, subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      if (!previous && this.list(ownerId).length >= CONNECTION_LIMIT) fail(409, 'connection_limit', `登録できる接続は${CONNECTION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID(), sealed = this.vault.seal(state, `connection:${ownerId}:${id}`);
      if (existing) this.db.prepare("UPDATE connections SET connector=?,subject=?,label=?,state=?,status='connected',generation=generation+1,updated_at=? WHERE id=?").run(connector, subject, label, sealed, stamp, id);
      else this.db.prepare("INSERT INTO connections (id,owner_id,connector,subject,label,state,status,kept_by,created_at,updated_at) VALUES (?,?,?,?,?,?,'connected',?,?,?)").run(id, ownerId, connector, subject, label, sealed, keptBy, stamp, stamp);
      return this.get(ownerId, id);
    });
  }
  saveState(row, state) {
    return this.store.transaction(() => {
      this.current(row);
      this.db.prepare('UPDATE connections SET state=?,updated_at=? WHERE id=?').run(this.vault.seal(state, `connection:${row.owner_id}:${row.id}`), now(), row.id);
    });
  }
  reconnectRequired(row) {
    this.db.prepare("UPDATE connections SET status='reconnect_required',generation=generation+1,updated_at=? WHERE id=? AND owner_id=? AND generation=? AND status='connected'").run(now(), row.id, row.owner_id, row.generation);
  }
  disconnect(ownerId, id) {
    return this.store.transaction(() => {
      const row = this.at(ownerId, id);
      this.db.prepare("UPDATE connections SET status='disconnecting',generation=generation+1,updated_at=? WHERE id=?").run(now(), row.id);
      return row;
    });
  }
  remove(ownerId, id) { return this.db.prepare('DELETE FROM connections WHERE owner_id=? AND id=?').run(ownerId, id).changes > 0; }
  view(row, { owner = false } = {}) {
    const connector = this.connectors.get(row.connector), state = this.state(row);
    if (!owner) return { id: row.id, connector: row.connector, service: connector.service, label: state.facts.label || row.label, status: row.status, facts: state.facts,
      access: connector.access, api: connector.service?.api || { base_url: '', documentation_url: '' }, outputs: connector.variables };
    const { owner_id: _owner, state: _state, ...publicRow } = row;
    return { ...publicRow, ...state.facts, expires_at: state.expires_at, access: connector.access, service: connector.service, outputs: connector.variables,
      ...(connector.revocationNote ? { revocation_note: connector.revocationNote } : {}), can_reconnect: connector.canReconnect !== false, can_revoke: typeof connector.revoke === 'function', available: connector.available };
  }
  outputs(connector, credentials) {
    if (!credentials || typeof credentials !== 'object') invalidResult();
    const values = new Map();
    const add = (key, content, filename) => {
      if (!connector.variables.includes(key) || values.has(key)) invalidResult();
      if (content.length > VALUE_MAX * 4) fail(502, 'service_response', '受け取った内容が大きすぎます。');
      values.set(key, { content, ...(filename ? { filename } : {}) });
    };
    for (const [key, value] of Object.entries(credentials.environment || {})) {
      if (typeof value !== 'string') invalidResult();
      add(key, Buffer.from(value, 'utf8'));
    }
    for (const file of credentials.files || []) add(file.env, Buffer.from(file.content, 'utf8'), file.filename);
    return values;
  }
  current(row) {
    const current = this.get(row.owner_id, row.id);
    if (!current || current.generation !== row.generation) fail(409, 'connection_changed', '接続状態が変わりました。');
    if (current.status !== 'connected') fail(409, 'reconnect_required', 'この接続は利用できません。接続し直してください。');
    return current;
  }
  // One credential operation per connection generation, including persistence. This also
  // preserves rotated private state when a caller's authorization or snapshot save fails.
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
    const connector = this.connectors.get(row.connector);
    try {
      const result = await connector.obtain(this.context(row));
      if (result?.subject !== row.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
      const state = this.nextState(result);
      this.saveState(row, state);
      return { state, values: this.outputs(connector, result.credentials) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed', 'refresh_missing'].includes(error.code)) this.reconnectRequired(row);
      throw error;
    }
  }
}
