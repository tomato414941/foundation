import { fail } from './errors.mjs';

// What a request does across the rest of Foundation: asked, answered call by call, declined, withdrawn. Each change
// and what records it commit together; notifications run only after the transaction has committed.
export class RequestActions {
  constructor({ store, requests, connections, principals, auditLog, changed = () => {} }) {
    Object.assign(this, { store, requests, connections, principals, auditLog, changed });
  }
  // One with no line to anyone yet - nobody knows it - may ask only to act for whoever answers, and that answer needs
  // the code it shows. That is the one call such a request may hold: a line from the asker, agent, onto the one who
  // makes it (me). Anyone already on a line names whom it asks.
  ask(fromId, { operations, toId, ...rest }) {
    const first = toId === null;
    if (first && !(operations.length === 1 && isTakingOn(operations[0], fromId))) fail(400, 'invalid_operations', 'まだ関係がない相手に頼めるのは、自分を代理（agent）にしてもらうことだけです。');
    const row = this.requests.create(fromId, { operations, toId, requesterName: this.principals.get(fromId)?.name ?? '', code: first, ...rest });
    this.auditLog.write(fromId, 'request.asked', 'request', row.id, { to: toId, operations: operations.map(call => call.method + ' ' + call.path) });
    return row;
  }
  // One call made by the one asked, and what it answered. The last one grants the request; one asked of nobody yet
  // leaves the asker owned by whoever answered it, as it had no owner.
  answer(id, toId, index, result) {
    const done = this.store.transaction(() => {
      const row = this.requests.answer(id, toId, index, result);
      this.requests.record(id, 'answered', { code: String(index) });
      if (row.status === 'granted') {
        if (row.user_code && !this.principals.ownersOf(row.from_id).length) this.principals.relate(toId, 'owner', 'principal', row.from_id);
        this.requests.record(id, 'granted');
        this.auditLog.write(toId, 'request.granted', 'request', id, {});
      }
      return row;
    });
    if (done.status === 'granted') this.changed(done);
    return done;
  }
  // A connection made by a flow that began as a call of a request (request: { id, index }), or by itself.
  connect(request, ownerId, service, scheme, result, { requestedBy = '', previous, scopes, app = null, name } = {}) {
    const saved = this.store.transaction(() => {
      if (request) this.requests.forTo(request.id, ownerId, true);
      const saved = this.connections.save(ownerId, service, scheme, result, { previous, scopes, app, name });
      this.auditLog.write(ownerId, previous ? 'connection.renewed' : 'connection.created', 'connection', saved.id, { service, auth_scheme: scheme, requested_by: requestedBy || null, request: request?.id ?? null });
      if (request) this.answer(request.id, ownerId, request.index, { status: previous ? 200 : 201, body: { connection: this.connections.view(saved, { owner: true }) } });
      return saved;
    });
    return saved;
  }
  deny(id, toId) {
    this.requests.deny(id, toId);
    this.requests.record(id, 'denied');
    const row = this.requests.get(id);
    this.auditLog.write(toId, 'request.denied', 'request', id, {});
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

// The call that takes on one nobody knows yet: its line, agent, onto whoever makes the call.
export const isTakingOn = (call, fromId) => call.method === 'POST' && call.path === '/v1/principals/' + fromId + '/relations' && !call.inputs
  && Object.keys(call.body ?? {}).length === 3 && call.body.relation === 'agent' && call.body.object_type === 'principal' && call.body.object_id === 'me';
