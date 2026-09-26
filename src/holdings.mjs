import { fail } from './errors.mjs';

// What it is to be held. Every holding, whatever its kind, has an id, a holder, a name the holder calls it by,
// lines drawn onto it and records about it; it is listed, renamed and removed by the same rules. What differs by
// kind is only what is done with the content, and that lives with the kind (secrets, objects, connections).
export const KINDS = ['secret', 'object', 'connection'];
// The columns every kind shares. A kind reads its own columns (content, connector, ...) itself.
const COMMON = 'id,holder_id,kind,name,size,type,created_at,updated_at';
const now = () => new Date().toISOString();

export class Holdings {
  constructor(store) { this.store = store; this.db = store.db; }

  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COMMON} FROM holdings WHERE id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  find(holderId, kind, name) {
    return this.db.prepare(`SELECT ${COMMON} FROM holdings WHERE holder_id=? AND kind=? AND name=?`).get(holderId, kind, name);
  }
  // What a holder has of one kind, by name, optionally only those whose name begins with a literal prefix.
  list(holderId, kind, prefix) {
    return prefix === undefined
      ? this.db.prepare(`SELECT ${COMMON} FROM holdings WHERE holder_id=? AND kind=? ORDER BY name`).all(holderId, kind)
      : this.db.prepare(`SELECT ${COMMON} FROM holdings WHERE holder_id=? AND kind=? AND substr(name,1,length(?))=? COLLATE BINARY ORDER BY name`).all(holderId, kind, String(prefix), String(prefix));
  }
  usage(holderId, kind) {
    return this.db.prepare('SELECT COUNT(*) AS count, COALESCE(SUM(size),0) AS bytes FROM holdings WHERE holder_id=? AND kind=?').get(holderId, kind);
  }
  // A kind places a row with its own columns besides the common ones. The id and the timestamps are given here.
  insert(id, holderId, kind, name, columns = {}) {
    const stamp = now(), fields = { id, holder_id: holderId, kind, name, created_at: stamp, updated_at: stamp, ...columns };
    const names = Object.keys(fields);
    this.db.prepare(`INSERT INTO holdings (${names.join(',')}) VALUES (${names.map(() => '?').join(',')})`).run(...names.map(name => fields[name]));
    return this.get(id);
  }
  update(id, columns) {
    const fields = { ...columns, updated_at: now() }, names = Object.keys(fields);
    this.db.prepare(`UPDATE holdings SET ${names.map(name => name + '=?').join(',')} WHERE id=?`).run(...names.map(name => fields[name]), id);
    return this.get(id);
  }
  // A new name for the same thing. Lines, records and the content stay: they point at the id.
  rename(row, name) {
    if (name !== row.name && this.find(row.holder_id, row.kind, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.update(row.id, { name });
  }
  // Removing the thing removes the lines onto it: a later thing by the same name is another thing.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare('DELETE FROM holdings WHERE id=?').run(row.id);
      this.db.prepare("DELETE FROM relations WHERE object_type='holding' AND object_id=?").run(row.id);
    });
  }
  // Everything a holder has, when the holder goes.
  removeAll(holderId) {
    this.store.transaction(() => {
      this.db.prepare("DELETE FROM relations WHERE object_type='holding' AND object_id IN (SELECT id FROM holdings WHERE holder_id=?)").run(holderId);
      this.db.prepare('DELETE FROM holdings WHERE holder_id=?').run(holderId);
    });
  }
  // What is said about a holding to anyone: the common columns and nothing of the content.
  view(row) {
    return { id: row.id, kind: row.kind, name: row.name, size: row.size, type: row.type ?? null, holder_id: row.holder_id, created_at: row.created_at, updated_at: row.updated_at };
  }
}
