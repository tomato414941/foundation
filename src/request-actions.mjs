import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';
import { requestInput } from './request-input.mjs';
import { takesApps } from './apps.mjs';

// Operations crossing resource boundaries. Each local result and its request completion
// commit together; notifications run only after the transaction has committed.
export class RequestActions {
  constructor({ store, requests, secrets, credentials, services, apps, principals, authorization, auditLog, changed = () => {} }) {
    Object.assign(this, { store, requests, secrets, credentials, services, apps, principals, authorization, auditLog, changed });
  }
  // A request is checked against what is there when it is made, so a mismatch reaches the requester and never the
  // one asked. A secret's name already in use must be declared a replacement, and a replacement must name something
  // that exists (the same rule is applied again when it is completed, see save). A connection must be one the one
  // asked can make: through an app they may use, or Foundation's when it has one - asking for a connection nobody
  // can complete would leave them at a dead end.
  ask(fromId, { kind, input, toId, ...rest }) {
    const definition = requestInput(kind, input);
    if (kind === 'store') for (const field of definition.fields) this.placement(toId, field, field.name);
    if (kind === 'app') this.apps.fields(this.services.get(definition.service, toId).ref);
    if (kind === 'connect') {
      const { ref, definition: service } = this.services.get(definition.service, toId);
      definition.auth_scheme ??= Object.keys(service.auth_schemes)[0];
      const scheme = this.services.scheme(ref, definition.auth_scheme);
      if (definition.scopes && !scheme.scopes) fail(400, 'scopes_unsupported', 'この接続方法では権限を指定できません。');
      if (definition.app !== undefined && !takesApps(scheme)) fail(400, 'app_unsupported', 'この接続方法はアプリを通しません。');
      const previous = definition.credential_id === undefined ? undefined : this.credentials.reconnection(toId, ref, definition.auth_scheme, definition.credential_id);
      if (definition.app !== undefined && definition.app !== 'foundation') {
        const app = this.apps.get(definition.app);
        if (!app || !this.authorization.can(toId, 'use', 'app', { id: app.id, holder: app.holder_id })) fail(404, 'not_found', 'アプリが見つかりません。');
        if (app.service !== ref) fail(400, 'app_mismatch', 'このアプリは別のサービスのものです。');
      } else if (takesApps(scheme) && !(definition.app === undefined && previous?.app_id) && !scheme.oauthClient.enabled) {
        fail(409, 'app_required', 'このサービスにはFoundationのアプリがありません。先にOAuthアプリの登録を依頼してください（kind "app"）。');
      } else if (!takesApps(scheme) && !scheme.available) fail(503, 'scheme_unavailable', '現在この方法では接続できません。');
    }
    const row = this.requests.create(fromId, { kind, input: definition, toId, ...rest });
    this.auditLog.write(fromId, 'request.asked', 'request', row.id, { kind, to: toId });
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
      const names = entries.map(entry => resourceName(entry.name));
      if (new Set(names).size !== names.length) fail(400, 'duplicate_names', '保存名が重複しています。別の名前を入力してください。');
      // The one asked may have given a replacement another name; then the existing value stays and this one is new.
      const targets = asked.map((one, at) => this.placement(toId, one, names[at]));
      for (const [at, one] of asked.entries()) {
        const existing = targets[at];
        const saved = this.secrets.put(toId, { name: names[at], content: Buffer.from(entries[at].content, 'utf8') });
        // Asked to read it back, the asker is put on a line to it; a value that already existed keeps its lines as they were.
        if (!existing && one.readable) this.principals.relate(row.from_id, 'viewer', 'resource', saved.id);
      }
      this.requests.done(id, toId, { names, replaced: names.filter((_, at) => targets[at]) });
      this.requests.record(id, 'stored');
      this.auditLog.write(toId, 'request.done', 'request', id, { kind: 'store', names });
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  // The one asked registers an app of theirs: its ID and secret go into the app, and the asker learns its id.
  registerApp(id, toId, input) {
    const done = this.store.transaction(() => {
      const row = this.requests.forTo(id, toId, true);
      if (row.kind !== 'app') fail(409, 'wrong_kind', 'この依頼はアプリの登録の依頼ではありません。');
      const asked = this.requests.input(row);
      if (this.apps.find(toId, input?.name ?? '')) fail(409, 'name_taken', 'その名前のアプリはすでにあります。別の名前を入力してください。');
      const app = this.apps.put(toId, { ...input, service: asked.service });
      this.auditLog.write(toId, 'app.created', 'resource', app.id, { service: asked.service, request: id });
      this.requests.done(id, toId, { app_id: app.id });
      this.requests.record(id, 'registered', { service: asked.service });
      this.auditLog.write(toId, 'request.done', 'request', id, { kind: 'app', service: asked.service });
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  // previous: the managed authorization this one replaces.
  connect(id, holderId, service, scheme, result, { requestedBy = '', previous, scopes, app = null } = {}) {
    const saved = this.store.transaction(() => {
      if (id) {
        const row = this.requests.forTo(id, holderId, true);
        const input = this.requests.input(row);
        if (row.kind !== 'connect' || input.service !== service || input.auth_scheme !== scheme) fail(409, 'wrong_kind', '依頼された方法で接続してください。');
        if (input.credential_id !== previous?.id) fail(409, 'credential_changed', '依頼された接続を選んでください。');
      }
      const saved = this.credentials.save(holderId, service, scheme, result, { previous, scopes, app });
      this.auditLog.write(holderId, previous ? 'credential.renewed' : 'credential.created', 'credential', saved.id, { service, auth_scheme: scheme, requested_by: requestedBy || null, request: id || null });
      if (id) {
        this.requests.done(id, holderId, { credential_id: saved.id });
        this.requests.record(id, 'connected', { service });
        this.auditLog.write(holderId, 'request.done', 'request', id, { kind: 'connect', service });
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
      if (this.principals.actsFor(row.from_id).includes(toId)) fail(409, 'request_changed', '依頼元の状態が変わりました。新しい依頼を作ってもらってください。');
      this.principals.relate(toId, 'owner', 'principal', row.from_id);
      this.principals.relate(row.from_id, 'actor', 'principal', toId);
      this.requests.done(id, toId, { principal_id: row.from_id });
      this.requests.record(id, 'approved');
      this.auditLog.write(toId, 'relation.added', 'principal', row.from_id, { relation: 'actor', for: toId });
      return this.requests.get(id);
    });
    this.changed(done);
    return done;
  }
  deny(id, toId) {
    this.requests.deny(id, toId);
    this.requests.record(id, 'denied');
    const row = this.requests.get(id);
    this.auditLog.write(toId, 'request.denied', 'request', id, { kind: row.kind });
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
  revokeAccess(holderId, fromId) {
    const cancelled = this.store.transaction(() => {
      const removed = this.principals.revokeAccess(fromId, holderId);
      const rows = this.requests.cancelFrom(fromId, 'access_revoked', holderId);
      if (removed || rows.length) this.auditLog.write(holderId, 'access.revoked', 'principal', fromId, {});
      return rows;
    });
    for (const row of cancelled) this.changed(row);
  }
  // A principal removed takes its open requests with it. Whoever it acted for keeps everything. Who may remove it is
  // the route's question.
  removePrincipal(byId, id) {
    const cancelled = this.store.transaction(() => {
      const cancelled = this.requests.cancelFrom(id);
      this.principals.remove(id);
      this.auditLog.write(byId, 'principal.removed', 'principal', id, {});
      return cancelled;
    });
    for (const row of cancelled) this.changed(row);
  }
}
