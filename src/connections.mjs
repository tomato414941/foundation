import { fail, HttpError } from './errors.mjs';
import { VALUE_MAX } from './secrets.mjs';
import { randomUUID } from 'node:crypto';

const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');
export const CONNECTION_LIMIT = 50;
const now = () => new Date().toISOString();
const COLUMNS = 'id, holder_id, kind, name, size, type, connector, subject, status, generation, created_at, updated_at';

export class Connections {
  constructor(store, connectors, holdings) { this.store = store; this.db = store.db; this.vault = store.vault; this.connectors = connectors; this.holdings = holdings; this.pending = new Map(); }
  // A connection is a holding whose content is the connector's state. Its name is the label the service gave.
  list(holderId) { return this.db.prepare(`SELECT ${COLUMNS} FROM holdings WHERE kind='connection' AND holder_id=? ORDER BY created_at,id`).all(holderId); }
  get(holderId, id) { return this.db.prepare(`SELECT ${COLUMNS} FROM holdings WHERE kind='connection' AND holder_id=? AND id=?`).get(holderId, id); }
  at(holderId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_connection', '接続IDを指定してください。');
    const row = this.get(holderId, id);
    if (!row) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  state(row) { return this.vault.open(this.db.prepare('SELECT content FROM holdings WHERE id=?').get(row.id).content, `connection:${row.holder_id}:${row.id}`); }
  context(row) { return row ? { subject: row.subject, privateState: this.state(row).private_state } : undefined; }
  nextState(result) {
    if (!result || typeof result.subject !== 'string' || !result.subject || result.subject.length > 512
      || !Object.hasOwn(result, 'privateState') || result.privateState === undefined
      || !result.facts || typeof result.facts !== 'object' || Array.isArray(result.facts)
      || (result.expiresAt !== null && !(Number.isFinite(result.expiresAt) && result.expiresAt > Date.now()))) invalidResult();
    return { private_state: result.privateState, facts: result.facts, expires_at: result.expiresAt };
  }
  save(holderId, connectorId, result, { previous } = {}) {
    this.connectors.get(connectorId);
    const state = this.nextState(result);
    if (previous && result.subject !== previous.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
    const label = String(state.facts.label || result.subject).slice(0, 80);
    return this.write(holderId, { connector: connectorId, subject: result.subject, label, state }, previous);
  }
  // Identity and renewal state belong to the connection, independently of saved values or requests.
  write(holderId, { connector, subject, label, state }, previous) {
    return this.store.transaction(() => {
      const existing = previous ? this.get(holderId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        if (existing.subject !== subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
      }
      if (!previous && this.db.prepare("SELECT 1 FROM holdings WHERE kind='connection' AND holder_id=? AND connector=? AND subject=?").get(holderId, connector, subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      if (!previous && this.list(holderId).length >= CONNECTION_LIMIT) fail(409, 'connection_limit', `登録できる接続は${CONNECTION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID(), sealed = this.vault.seal(state, `connection:${holderId}:${id}`);
      if (existing) this.holdings.update(id, { connector, subject, name: label, content: sealed, status: 'connected', generation: existing.generation + 1 });
      else this.holdings.insert(id, holderId, 'connection', label, { content: sealed, connector, subject, status: 'connected' });
      return this.get(holderId, id);
    });
  }
  saveState(row, state) {
    return this.store.transaction(() => {
      this.current(row);
      this.holdings.update(row.id, { content: this.vault.seal(state, `connection:${row.holder_id}:${row.id}`) });
    });
  }
  reconnectRequired(row) {
    this.db.prepare("UPDATE holdings SET status='reconnect_required',generation=generation+1,updated_at=? WHERE id=? AND holder_id=? AND generation=? AND status='connected'").run(now(), row.id, row.holder_id, row.generation);
  }
  disconnect(holderId, id) {
    return this.store.transaction(() => {
      const row = this.at(holderId, id);
      this.db.prepare("UPDATE holdings SET status='disconnecting',generation=generation+1,updated_at=? WHERE id=?").run(now(), row.id);
      return row;
    });
  }
  remove(holderId, id) {
    const row = this.get(holderId, id);
    if (row) this.holdings.remove(row);
    return Boolean(row);
  }
  view(row, { owner = false } = {}) {
    const connector = this.connectors.get(row.connector), state = this.state(row);
    if (!owner) return { id: row.id, connector: row.connector, service: connector.service, label: state.facts.label || row.name, status: row.status, facts: state.facts,
      access: connector.access, api: connector.service?.api || { base_url: '', documentation_url: '' }, outputs: connector.variables };
    const { holder_id: _holder, kind: _kind, size: _size, type: _type, name, ...publicRow } = row;
    return { ...publicRow, label: name, ...state.facts, expires_at: state.expires_at, access: connector.access, service: connector.service, outputs: connector.variables,
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
    const current = this.get(row.holder_id, row.id);
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
