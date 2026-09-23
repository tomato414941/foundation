import { fail, HttpError } from './errors.mjs';
import { VALUE_MAX } from './secrets.mjs';

// OAuth state and provider operations. Ordinary saved values are not part of this interface.
// Provider code accepts a value and returns a value; it never receives a storage handle.
export class Acquisitions {
  constructor(store, adapters) { this.store = store; this.adapters = adapters; }
  state(acquisition) { return this.store.acquisitionState(acquisition); }
  nextState(adapter, secret) {
    return { renewal: secret, facts: adapter.client.facts?.(secret) || {}, expires_at: secret.expires_at ?? null };
  }
  save(ownerId, adapterId, result, { keptBy = '', previous } = {}) {
    const adapter = this.adapters.get(adapterId), state = this.nextState(adapter, result.secret);
    const label = String(state.facts.label || result.subject).slice(0, 80);
    return this.store.saveAcquisition(ownerId, { adapter: adapterId, subject: result.subject, label, keptBy, state }, previous);
  }
  outputs(adapterId, secret, subject) {
    const adapter = this.adapters.get(adapterId), delivered = adapter.deliver(secret, { subject }) || {};
    const values = new Map();
    const add = (key, content, filename) => {
      if (!adapter.variables.includes(key) || values.has(key)) fail(502, 'service_response', '接続先からの出力を確認できませんでした。');
      if (content.length > VALUE_MAX * 4) fail(502, 'service_response', '受け取った内容が大きすぎます。');
      values.set(key, { content, ...(filename ? { filename } : {}) });
    };
    for (const [key, value] of Object.entries(delivered.environment || {})) add(key, Buffer.from(String(value), 'utf8'));
    for (const file of delivered.files || []) add(file.env, Buffer.from(file.content, 'utf8'), file.filename);
    return values;
  }
  // Explicitly invoked by a caller. Returning the result does not modify any ordinary saved value.
  async obtain(acquisition) {
    const adapter = this.adapters.get(acquisition.adapter);
    if (acquisition.status !== 'connected') fail(409, 'reconnect_required', 'この接続は利用できません。接続し直してください。');
    try {
      const secret = await adapter.client.token(this.state(acquisition).renewal, acquisition, false);
      return { state: this.nextState(adapter, secret), values: this.outputs(adapter.id, secret, acquisition.subject) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'scope_mismatch', 'account_changed', 'refresh_missing'].includes(error.code)) this.store.reconnectRequired(acquisition);
      throw error;
    }
  }
}
