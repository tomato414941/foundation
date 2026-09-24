import { fail, HttpError } from './errors.mjs';
import { VALUE_MAX } from './secrets.mjs';

const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');

export class Connections {
  constructor(store, connectors) { this.store = store; this.connectors = connectors; this.pending = new Map(); }
  state(row) {
    const state = this.store.acquisitionState(row);
    // Read previously encrypted records as-is. New writes use a provider-neutral envelope.
    return { private_state: Object.hasOwn(state, 'private_state') ? state.private_state : state.renewal,
      facts: state.facts || {}, expires_at: state.expires_at ?? null };
  }
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
    return this.store.saveAcquisition(ownerId, { adapter: connectorId, subject: result.subject, label, keptBy, state }, previous);
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
    const current = this.store.acquisition(row.owner_id, row.id);
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
    const connector = this.connectors.get(row.adapter);
    try {
      const result = await connector.obtain(this.context(row));
      if (result?.subject !== row.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
      const state = this.nextState(result);
      this.store.saveState(row, state);
      return { state, values: this.outputs(connector, result.credentials) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed', 'refresh_missing'].includes(error.code)) this.store.reconnectRequired(row);
      throw error;
    }
  }
}
