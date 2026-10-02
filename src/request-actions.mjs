import { fail } from './errors.mjs';
import { bytes as keyBytes } from './keys.mjs';
import { resourceName } from './resources.mjs';
import { takesApps } from './apps.mjs';
import { reaches } from './authorization.mjs';

// Operations crossing resource boundaries. Each local result and its request completion
// commit together; notifications run only after the transaction has committed.
export class RequestActions {
  constructor({ store, requests, secrets, connections, services, apps, principals, authorization, auditLog, changed = () => {} }) {
    Object.assign(this, { store, requests, secrets, connections, services, apps, principals, authorization, auditLog, changed });
  }
  // A request is checked against what is there when it is made, so a mismatch reaches the requester and never the
  // one asked. A secret's name already in use must be declared a replacement, and a replacement must name something
  // that exists (the same rule is applied again when it is completed, see save). A connection must be one the one
  // asked can make: through an app they may use, or Foundation's when it has one - asking for a connection nobody
  // can complete would leave them at a dead end.
  ask(fromId, { type, detail: definition, toId, ...rest }) {
    if (type === 'secret') for (const field of definition.fields) this.placement(toId, field, field.name);
    if (type === 'app') this.apps.fields(this.services.get(definition.service, toId).ref);
    if (type === 'relation') this.relationAsked(fromId, toId, definition);
    if (type === 'connection') {
      const { ref, definition: service } = this.services.get(definition.service, toId);
      definition.auth_scheme ??= Object.keys(service.auth_schemes)[0];
      const scheme = this.services.scheme(ref, definition.auth_scheme);
      if (definition.scopes && !scheme.scopes) fail(400, 'scopes_unsupported', 'この接続方法では権限を指定できません。');
      if (definition.app !== undefined && !takesApps(scheme)) fail(400, 'app_unsupported', 'この接続方法はアプリを通しません。');
      const previous = definition.connection_id === undefined ? undefined : this.connections.reconnection(toId, ref, definition.auth_scheme, definition.connection_id);
      if (definition.app !== undefined && definition.app !== 'foundation') {
        const app = this.apps.get(definition.app);
        if (!app || !this.authorization.can(toId, 'use', 'app', { id: app.id, owner: app.owner_id })) fail(404, 'not_found', 'アプリが見つかりません。');
        if (app.service !== ref) fail(400, 'app_mismatch', 'このアプリは別のサービスのものです。');
      } else if (takesApps(scheme) && !(definition.app === undefined && previous?.app_id) && !scheme.oauthClient.enabled) {
        fail(409, 'app_required', 'このサービスにはFoundationのアプリがありません。先にOAuthアプリの登録を依頼してください（type "app"）。');
      } else if (!takesApps(scheme) && !scheme.available) fail(503, 'scheme_unavailable', '現在この方法では接続できません。');
    }
    const row = this.requests.create(fromId, { type, detail: definition, toId, requesterName: this.principals.get(fromId)?.name ?? '', code: type === 'relation' && this.firstContact(fromId, toId, definition), ...rest });
    this.auditLog.write(fromId, 'request.asked', 'request', row.id, { type, to: toId });
    return row;
  }
  // A relation may be drawn where the rules let it be drawn. Asked by one with no line yet to the one asked - named or
  // not - it is first contact: the only thing to ask is to act for them, and the answer needs the asker's code. Asked
  // by one already on a line to them or to what it asks about, it is asked where they are.
  relationAsked(fromId, toId, { relation, object_type, object_id }) {
    if (this.firstContact(fromId, toId, { object_type, object_id })) {
      if (relation !== 'agent' || object_type !== undefined) fail(400, 'invalid_authorization_details', 'まだ関係がない相手に頼めるのは、持ち物を使うこと（agent）だけです。');
      return;
    }
    const object = this.objectOf(toId, { relation, object_type, object_id });
    if (!reaches(relation, object.type === 'principal' ? 'principal' : object.kind)) fail(400, 'invalid_authorization_details', '関係の種類を確認してください。');
  }
  // Whether the one asking has no line yet to the one asked, nor to what it asks about.
  firstContact(fromId, toId, { object_type, object_id } = {}) {
    if (toId === null) return true;
    return !this.principals.relationsOf(fromId).some(line => line.subject_id === fromId
      && ((line.object_type === 'principal' && line.object_id === toId) || (object_type === 'resource' && line.object_type === 'resource' && line.object_id === object_id)));
  }
  // What a relation is drawn onto: the one named, or the one answering when none is.
  objectOf(toId, { object_type, object_id }) {
    if (object_type === undefined) return { type: 'principal', id: toId };
    if (object_type === 'principal') return { type: 'principal', id: this.principals.at(object_id).id };
    const held = this.secrets.resources.at(object_id);
    if (held.owner_id !== toId) fail(400, 'invalid_authorization_details', '依頼する相手の持ち物を指定してください。');
    return { type: 'resource', id: held.id, kind: held.kind, owner_id: held.owner_id };
  }
  // Where one value will go: new under a free name, or in place of what a replacement names. Nothing
  // else: a request never overwrites what it did not declare it would.
  placement(ownerId, asked, name) {
    const existing = this.secrets.find(ownerId, name), replacing = asked.replace && name === asked.name;
    if (replacing && !existing) fail(409, 'name_missing', `「${name}」という保存値はありません。置き換えではなく、新しく預ける依頼にしてください。`);
    if (!replacing && existing) fail(409, 'name_taken', `「${name}」はすでに使われています。別の保存名を入力してください。`);
    return replacing ? existing : null;
  }
  save(id, toId, entries) {
    const done = this.store.transaction(() => {
      const row = this.requests.forTo(id, toId, true);
      if (row.type !== 'secret') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
      const asked = this.requests.detail(row).fields;
      if (!Array.isArray(entries) || entries.length !== asked.length || entries.some(entry => !entry || typeof entry.content !== 'string')) fail(400, 'invalid_values', '入力内容を確認してください。');
      const sealed = entries.map(entry => { const content = keyBytes(entry.content); if (!content || content.length < 29) fail(400, 'invalid_values', '入力内容を確認してください。'); return content; });
      const names = entries.map(entry => resourceName(entry.name));
      if (new Set(names).size !== names.length) fail(400, 'duplicate_names', '保存名が重複しています。別の名前を入力してください。');
      // The one asked may have given a replacement another name; then the existing value stays and this one is new.
      const targets = asked.map((one, at) => this.placement(toId, one, names[at]));
      for (const [at, one] of asked.entries()) {
        const existing = targets[at];
        const saved = this.secrets.put(toId, { name: names[at], content: sealed[at], envelopes: entries[at].envelopes });
        // Asked to read it back, the asker is put on a line to it; a value that already existed keeps its lines as they were.
        if (!existing && one.readable) this.principals.relate(row.from_id, 'viewer', 'resource', saved.id);
      }
      this.requests.done(id, toId, { names, replaced: names.filter((_, at) => targets[at]) });
      this.requests.record(id, 'stored');
      this.auditLog.write(toId, 'request.granted', 'request', id, { type: 'secret', names });
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  // The one asked registers an app of theirs: its ID and secret go into the app, and the asker learns its id.
  registerApp(id, toId, input) {
    const done = this.store.transaction(() => {
      const row = this.requests.forTo(id, toId, true);
      if (row.type !== 'app') fail(409, 'wrong_kind', 'この依頼はアプリの登録の依頼ではありません。');
      const asked = this.requests.detail(row);
      if (this.apps.find(toId, input?.name ?? '')) fail(409, 'name_taken', 'その名前のアプリはすでにあります。別の名前を入力してください。');
      const app = this.apps.put(toId, { ...input, service: asked.service });
      this.auditLog.write(toId, 'app.created', 'resource', app.id, { service: asked.service, request: id });
      this.requests.done(id, toId, { app_id: app.id });
      this.requests.record(id, 'registered', { service: asked.service });
      this.auditLog.write(toId, 'request.granted', 'request', id, { type: 'app', service: asked.service });
      return this.requests.get(id);
    });
    this.changed(done);
    return JSON.parse(done.result);
  }
  // previous: the managed authorization this one replaces.
  connect(id, ownerId, service, scheme, result, { requestedBy = '', previous, scopes, app = null, name } = {}) {
    const saved = this.store.transaction(() => {
      if (id) {
        const row = this.requests.forTo(id, ownerId, true);
        const input = this.requests.detail(row);
        if (row.type !== 'connection' || input.service !== service || input.auth_scheme !== scheme) fail(409, 'wrong_kind', '依頼された方法で接続してください。');
        if (input.connection_id !== previous?.id) fail(409, 'connection_changed', '依頼された接続を選んでください。');
      }
      const saved = this.connections.save(ownerId, service, scheme, result, { previous, scopes, app, name });
      this.auditLog.write(ownerId, previous ? 'connection.renewed' : 'connection.created', 'connection', saved.id, { service, auth_scheme: scheme, requested_by: requestedBy || null, request: id || null });
      if (id) {
        this.requests.done(id, ownerId, { connection_id: saved.id });
        this.requests.record(id, 'connected', { service });
        this.auditLog.write(ownerId, 'request.granted', 'request', id, { type: 'connection', service });
      }
      return saved;
    });
    if (id) this.changed(this.requests.get(id));
    return saved;
  }
  // The one asked draws the relation asked for, by the same rule as any line they draw. Asked of nobody yet, the one
  // who answers types the code the asker showed, is who the relation is onto, and owns the asker from then on.
  grantRelation(id, toId, code) {
    const first = Boolean(this.requests.forTo(id, toId, true).user_code);
    if (first) this.requests.verifyCode(id, toId, code);
    const done = this.store.transaction(() => {
      const row = first ? this.requests.verifyCode(id, toId, code) : this.requests.forTo(id, toId, true);
      if (row.type !== 'relation') fail(409, 'wrong_kind', 'この依頼は関係の依頼ではありません。');
      const asked = this.requests.detail(row), object = this.objectOf(toId, asked);
      if (!this.authorization.mayGive(toId, asked.relation, object.type, object.type === 'principal' ? { id: object.id } : object)) fail(403, 'forbidden', 'この関係を引く権限がありません。');
      if (asked.relation === 'agent' && this.principals.actsFor(row.from_id).includes(object.id)) fail(409, 'request_changed', '依頼元の状態が変わりました。新しい依頼を作ってもらってください。');
      if (first && !this.principals.ownersOf(row.from_id).length) this.principals.relate(toId, 'owner', 'principal', row.from_id);
      this.principals.relate(row.from_id, asked.relation, object.type, object.id);
      this.requests.done(id, toId, { relation: asked.relation, object_type: object.type, object_id: object.id });
      this.requests.record(id, 'granted');
      this.auditLog.write(toId, 'relation.added', object.type, object.id, { subject: row.from_id, relation: asked.relation, request: id });
      return this.requests.get(id);
    });
    this.changed(done);
    return done;
  }
  deny(id, toId) {
    this.requests.deny(id, toId);
    this.requests.record(id, 'denied');
    const row = this.requests.get(id);
    this.auditLog.write(toId, 'request.denied', 'request', id, { type: row.type });
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
  revokeAccess(ownerId, fromId) {
    const cancelled = this.store.transaction(() => {
      const removed = this.principals.revokeAccess(fromId, ownerId);
      const rows = this.requests.cancelFrom(fromId, 'access_revoked', ownerId);
      if (removed || rows.length) this.auditLog.write(ownerId, 'access.revoked', 'principal', fromId, {});
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
