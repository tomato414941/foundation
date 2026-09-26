import { randomUUID } from 'node:crypto';

// What happened, written down as it happened: who did what to which thing, and how it went. Never what was
// typed or delivered. A principal reads the records it took part in, either as the one acting or as the thing
// acted upon.
export class Records {
  constructor(store) { this.db = store.db; }
  write(actorId, action, objectType, objectId, detail = {}) {
    const row = { id: randomUUID(), at: new Date().toISOString(), actor_id: actorId, action: String(action).slice(0, 40), object_type: String(objectType).slice(0, 20), object_id: String(objectId).slice(0, 200) };
    this.db.prepare('INSERT INTO records (id,at,actor_id,action,object_type,object_id,detail) VALUES (?,?,?,?,?,?,?)')
      .run(row.id, row.at, row.actor_id, row.action, row.object_type, row.object_id, JSON.stringify(detail).slice(0, 2000));
    return row;
  }
  list(principalId, { limit = 100 } = {}) {
    return this.db.prepare(`SELECT id,at,actor_id,action,object_type,object_id,detail FROM records
      WHERE actor_id=? OR (object_type='principal' AND object_id=?) ORDER BY at DESC, id DESC LIMIT ?`).all(principalId, principalId, limit)
      .map(row => ({ ...row, detail: JSON.parse(row.detail) }));
  }
}
