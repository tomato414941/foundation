import { fail } from './errors.mjs';
import { secretName } from './secrets.mjs';
import { requestInput } from './request-input.mjs';

// Operations crossing resource boundaries. Each local result and its request completion
// commit together; notifications run only after the transaction has committed.
export class RequestActions {
  constructor({ store, requests, secrets, connections, principals, records, changed = () => {} }) {
    Object.assign(this, { store, requests, secrets, connections, principals, records, changed });
  }
  // A store request is checked against what is kept when it is made, so a mismatch reaches the requester
  // and never the one asked: a name already in use must be declared a replacement, and a replacement must
  // name something that exists. The same rule is applied again when it is completed (see save).
  ask(fromId, { kind, input, toId, ...rest }) {
    const definition = requestInput(kind, input);
    if (kind === 'store') for (const field of definition.fields) this.placement(toId, field, field.name);
    const row = this.requests.create(fromId, { kind, input, toId, ...rest });
    this.records.write(fromId, 'request.asked', 'request', row.id, { kind, to: toId });
    return row;
  }
  // Where one value will go: new under a free name, or in place of what a replacement names. Nothing
  // else: a request never overwrites what it did not declare it would.
  placement(holderId, asked, name) {
    const existing = this.secrets.find(holderId, name), replacing = asked.replace && name === asked.name;
    if (replacing && !existing) fail(409, 'name_missing', `「${name}」という保存値はありません。置き換えではなく、新しく預ける依頼にしてください。`);
    if (!replacing && existing) fail(409, 'name_taken', `「${name}」はすでに使われています。別の保存名を入力してください。`);
    return replacing ? existing : null;
  }
  save(id, toId, entries) {
    const done = this.store.transaction(() => {
      const row = this.requests.forTo(id, toId, true);
      if (row.kind !== 'store') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
      const asked = this.requests.input(row).fields;
      if (!Array.isArray(entries) || entries.length !== asked.length || entries.some(entry => !entry || typeof entry.content !== 'string' || !entry.content)) fail(400, 'invalid_values', '入力内容を確認してください。');
      const names = entries.map(entry => secretName(entry.name));
      if (new Set(names).size !== names.length) fail(400, 'duplicate_names', '保存名が重複しています。別の名前を入力してください。');
      // The one asked may have given a replacement another name; then the existing value stays and this one is new.
      const targets = asked.map((one, at) => this.placement(toId, one, names[at]));
      for (const [at, one] of asked.entries()) {
        const existing = targets[at];
        this.secrets.put(toId, { name: names[at], content: Buffer.from(entries[at].content, 'utf8'), secret: existing ? !existing.readable : one.secret });
      }
      this.requests.done(id, toId, { names, replaced: names.filter((_, at) => targets[at]) });
      this.requests.record(id, 'stored');
      this.records.write(toId, 'request.done', 'request', id, { kind: 'store', names });
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  connect(id, holderId, connector, result, options) {
    const saved = this.store.transaction(() => {
      if (id) {
        const row = this.requests.forTo(id, holderId, true);
        if (row.kind !== 'connect' || this.requests.input(row).connector !== connector) fail(409, 'wrong_kind', '依頼された接続方法で登録してください。');
      }
      const saved = this.connections.save(holderId, connector, result, options);
      if (id) {
        this.requests.done(id, holderId, { connection_id: saved.id });
        this.requests.record(id, 'connected', { connector });
        this.records.write(holderId, 'request.done', 'request', id, { kind: 'connect', connector });
      }
      return saved;
    });
    if (id) this.changed(this.requests.get(id));
    return saved;
  }
  // The one asked accepts the asker as an actor: from then on the asker acts for them, and they own the asker.
  approve(id, toId, code) {
    this.requests.verifyCode(id, toId, code);
    const done = this.store.transaction(() => {
      const row = this.requests.verifyCode(id, toId, code);
      if (this.principals.actsFor(row.from_id).some(item => item.id === toId)) fail(409, 'request_changed', '依頼元の状態が変わりました。新しい依頼を作ってもらってください。');
      this.principals.relate(toId, 'owner', 'principal', row.from_id);
      this.principals.relate(row.from_id, 'actor', 'principal', toId);
      this.requests.done(id, toId, { principal_id: row.from_id });
      this.requests.record(id, 'approved');
      this.records.write(toId, 'relation.added', 'principal', row.from_id, { relation: 'actor', for: toId });
      return this.requests.get(id);
    });
    this.changed(done);
    return done;
  }
  deny(id, toId) {
    this.requests.deny(id, toId);
    this.requests.record(id, 'denied');
    const row = this.requests.get(id);
    this.records.write(toId, 'request.denied', 'request', id, { kind: row.kind });
    this.changed(row);
    return row;
  }
  cancel(fromId, id) {
    this.requests.cancel(fromId, id);
    this.requests.record(id, 'cancelled');
    const row = this.requests.get(id);
    this.changed(row);
    return row;
  }
  // A principal removed by its owner takes its open requests with it. Whoever it acted for keeps everything.
  removePrincipal(ownerId, id) {
    const cancelled = this.store.transaction(() => {
      if (!this.principals.has(ownerId, 'owner', 'principal', id)) fail(404, 'not_found', '相手が見つかりません。');
      const cancelled = this.requests.cancelFrom(id);
      this.principals.remove(id);
      this.records.write(ownerId, 'principal.removed', 'principal', id, {});
      return cancelled;
    });
    for (const row of cancelled) this.changed(row);
  }
}
