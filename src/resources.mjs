import { fail } from './errors.mjs';

// What it is to be a resource. Every resource has an id, a owner, a name the owner calls it by, lines drawn onto
// it and an audit log about it; it is listed, renamed and removed by the same rules. What a resource is lives in a
// table of its own kind, keyed by this id, and what is done with it belongs to that kind:
//   secret      private bytes whose purpose is the owner's (secrets.mjs)
//   connection  a managed authorization at a service (connections.mjs)
//   object      a file the owner placed here (objects.mjs)
//   app         an OAuth app, the name a service knows Foundation by (apps.mjs)
//   service     a service the owner described, for one the catalog does not know (services.mjs)
//   environment a machine lent to the owner, with a shell, files and the network (environments.mjs)
export const KINDS = ['secret', 'connection', 'object', 'app', 'service', 'environment'];
const COMMON = 'id,owner_id,kind,name,created_at,updated_at';
const now = () => new Date().toISOString();

// A name is what the owner calls a thing. It is not a path, a service, or an instruction.
export function resourceName(value) {
  if (typeof value !== 'string' || !value.length || value.length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(value) || !value.isWellFormed()) fail(400, 'invalid_name', '名前は制御文字を含まない1〜200文字で指定してください。');
  return value;
}

export class Resources {
  constructor(store) { this.store = store; this.db = store.db; }

  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COMMON} FROM resources WHERE id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  // The id and the timestamps are given here; the kind places its own row beside this one.
  insert(id, ownerId, kind, name) {
    const stamp = now();
    this.db.prepare('INSERT INTO resources (id,owner_id,kind,name,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(id, ownerId, kind, name, stamp, stamp);
    return this.get(id);
  }
  touch(id) { this.db.prepare('UPDATE resources SET updated_at=? WHERE id=?').run(now(), id); return this.get(id); }
  // A new name for the same thing. Lines, the audit log and the content stay: they point at the id. Whether the
  // name is free is the kind's question, asked before this.
  rename(row, name) { this.db.prepare('UPDATE resources SET name=?,updated_at=? WHERE id=?').run(name, now(), row.id); return this.get(row.id); }
  // Removing the thing removes its kind's row (by cascade) and the lines onto it: a later thing by the same
  // name is another thing.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare('DELETE FROM resources WHERE id=?').run(row.id);
      this.db.prepare("DELETE FROM relations WHERE object_type='resource' AND object_id=?").run(row.id);
    });
  }
  // Everything a owner has, when the owner goes.
  removeAll(ownerId) {
    this.store.transaction(() => {
      this.db.prepare("DELETE FROM relations WHERE object_type='resource' AND object_id IN (SELECT id FROM resources WHERE owner_id=?)").run(ownerId);
      this.db.prepare('DELETE FROM resources WHERE owner_id=?').run(ownerId);
    });
  }
  // What is said about a resource to anyone: the common columns and nothing of the content.
  view(row) {
    return { id: row.id, kind: row.kind, name: row.name, owner_id: row.owner_id, created_at: row.created_at, updated_at: row.updated_at };
  }
}
