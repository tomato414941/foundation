import { fail } from './errors.mjs';
import { secretName } from './secrets.mjs';

// Operations crossing resource boundaries. Each local result and its request completion
// commit together; notifications run only after the transaction has committed.
export class RequestActions {
  constructor({ store, requests, secrets, connections, keys, changed = () => {} }) {
    Object.assign(this, { store, requests, secrets, connections, keys, changed });
  }
  save(id, ownerId, entries) {
    const done = this.store.transaction(() => {
      const row = this.requests.forUser(id, ownerId, true);
      if (row.kind !== 'store') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
      const asked = this.requests.input(row).fields;
      if (!Array.isArray(entries) || entries.length !== asked.length || entries.some(entry => !entry || typeof entry.content !== 'string' || !entry.content)) fail(400, 'invalid_values', '入力内容を確認してください。');
      const names = entries.map(entry => secretName(entry.name));
      if (new Set(names).size !== names.length) fail(400, 'duplicate_names', '保存名が重複しています。別の名前を入力してください。');
      const occupied = names.find(name => this.secrets.find(ownerId, name));
      if (occupied !== undefined) fail(409, 'name_taken', `「${occupied}」はすでに使われています。別の保存名を入力してください。`);
      for (const [at, one] of asked.entries()) this.secrets.put(ownerId, { name: names[at], content: Buffer.from(entries[at].content, 'utf8'), secret: one.secret });
      this.requests.done(id, ownerId, { names });
      this.requests.record(id, 'stored');
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  connect(id, ownerId, connector, result, options) {
    const saved = this.store.transaction(() => {
      if (id) {
        const row = this.requests.forUser(id, ownerId, true);
        if (row.kind !== 'connect' || this.requests.input(row).connector !== connector) fail(409, 'wrong_kind', '依頼された接続方法で登録してください。');
      }
      const saved = this.connections.save(ownerId, connector, result, options);
      if (id) {
        this.requests.done(id, ownerId, { connection_id: saved.id });
        this.requests.record(id, 'connected', { connector });
      }
      return saved;
    });
    if (id) this.changed(this.requests.get(id));
    return saved;
  }
  deny(id, ownerId) {
    this.requests.deny(id, ownerId);
    this.requests.record(id, 'denied');
    const row = this.requests.get(id);
    this.changed(row);
    return row;
  }
  cancel(token, id) {
    this.requests.cancel(token, id);
    this.requests.record(id, 'cancelled');
    const row = this.requests.get(id);
    this.changed(row);
    return row;
  }
  revokeKey(ownerId, id) {
    const cancelled = this.store.transaction(() => {
      const cancelled = this.requests.cancelForKey(ownerId, id);
      this.keys.remove(ownerId, id);
      return cancelled;
    });
    for (const row of cancelled) this.changed(row);
  }
  replaceKey(ownerId, id, name) {
    let cancelled = [];
    const key = this.store.transaction(() => {
      if (id !== undefined) {
        if (!this.keys.get(ownerId, id)) fail(404, 'not_found', '置き換えるキーが見つかりません。');
        cancelled = this.requests.cancelForKey(ownerId, id);
        this.keys.remove(ownerId, id);
      }
      return this.keys.create(ownerId, name);
    });
    for (const row of cancelled) this.changed(row);
    return key;
  }
}
