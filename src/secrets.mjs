import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';

// Private bytes, with no assumed purpose. An API key, a configuration file and a note are kept in the same way:
// sealed by whoever placed them, with the secret's own key, which comes with them in an envelope per recipient
// (keys.mjs). What is kept here is the sealed bytes; nothing here opens them.
export const SECRET_MAX = 1024 * 1024;
export const SECRET_COUNT_MAX = 200;
export const SECRET_TOTAL_MAX = 20 * 1024 * 1024;
const COLUMNS = 'r.id,r.owner_id,r.kind,r.name,r.created_at,r.updated_at,s.size,s.generation';
const FROM = 'FROM resources r JOIN secrets s ON s.resource_id=r.id';

export class Secrets {
  constructor(store, resources, keys) { Object.assign(this, { store, db: store.db, resources, keys }); }
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  held(ownerId, id) { const row = this.get(id); return row && row.owner_id === ownerId ? row : undefined; }
  find(ownerId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.owner_id=? AND r.name=?`).get(ownerId, resourceName(name)); }
  at(ownerId, name) {
    const row = this.find(ownerId, name);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  list(ownerId, { prefix } = {}) {
    return prefix === undefined ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.owner_id=? ORDER BY r.name,r.id`).all(ownerId)
      : this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.owner_id=? AND substr(r.name,1,length(?))=? COLLATE BINARY ORDER BY r.name,r.id`).all(ownerId, String(prefix), String(prefix));
  }
  usage(ownerId) { return this.db.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(s.size),0) AS bytes ${FROM} WHERE r.owner_id=?`).get(ownerId); }
  // The sealed bytes, as they were placed.
  content(row) {
    const sealed = this.db.prepare('SELECT content FROM secrets WHERE resource_id=?').get(row.id)?.content;
    if (sealed === undefined) fail(404, 'not_found', '見つかりません。');
    return Buffer.from(sealed);
  }
  // The bytes themselves, opened with what was sealed for Foundation's principal: for using them in its name.
  open(row) { return this.keys.openFor(row.id, this.content(row)); }
  // Placed sealed, with the envelopes its placer made. Placed by Foundation's principal, it seals the bytes itself.
  put(ownerId, { name, content, envelopes }) {
    resourceName(name);
    return this.store.transaction(() => {
      const existing = this.find(ownerId, name);
      if (existing) return this.write(existing, content, envelopes);
      this.checkSize(ownerId, content);
      if (this.usage(ownerId).count >= SECRET_COUNT_MAX) fail(409, 'secret_limit', `預けられるのは${SECRET_COUNT_MAX}件までです。使わないものを消してください。`);
      const id = randomUUID();
      this.resources.insert(id, ownerId, 'secret', name);
      this.db.prepare('INSERT INTO secrets (resource_id,size,content) VALUES (?,?,?)').run(id, content.length, content);
      this.keys.keepEnvelopes(id, envelopes);
      return this.get(id);
    });
  }
  // Placed unsealed, by one who cannot seal: Foundation's principal seals it, for the owner and itself. Over what
  // is there, the same key is kept, so every envelope stays good.
  putAs(ownerId, { name, content }) {
    return this.store.transaction(() => {
      const existing = this.find(ownerId, resourceName(name));
      if (existing) return this.writeAs(existing, content);
      const sealed = this.keys.sealAs(content, [ownerId]);
      return this.put(ownerId, { name, content: sealed.content, envelopes: sealed.envelopes });
    });
  }
  writeAs(row, content) { return this.write(row, this.keys.sealFor(row.id, content)); }
  checkSize(ownerId, content, previousSize = 0) {
    if (content.length > SECRET_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
    if (this.usage(ownerId).bytes - previousSize + content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '預けられる合計は20MBまでです。使わないものを消してください。');
  }
  write(row, content, envelopes) {
    return this.store.transaction(() => {
      const current = this.held(row.owner_id, row.id);
      if (!current || current.generation !== row.generation) fail(409, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
      this.checkSize(current.owner_id, content, current.size);
      this.db.prepare('UPDATE secrets SET size=?,content=?,generation=generation+1 WHERE resource_id=?').run(content.length, content, current.id);
      this.keys.keepEnvelopes(current.id, envelopes);
      this.resources.touch(current.id);
      return this.get(current.id);
    });
  }
  rename(row, name) {
    resourceName(name);
    if (name !== row.name && this.find(row.owner_id, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.get(this.resources.rename(row, name).id);
  }
  // Given to another owner, with an envelope for them when the giver made one, or when Foundation can make one
  // from its own; the giver's own envelope goes with their line. Without either, the new owner has the secret and not
  // yet its key.
  transfer(row, ownerId, envelope) {
    return this.store.transaction(() => {
      const moved = this.resources.transfer(row, ownerId);
      if (envelope !== undefined) this.keys.keepEnvelope(row.id, ownerId, envelope);
      else if (this.keys.envelopeOf(row.id, this.keys.agentId) && this.keys.publicKeyOf(ownerId)) this.keys.resealFor(row.id, ownerId);
      this.keys.dropEnvelope(row.id, row.owner_id);
      return this.get(moved.id);
    });
  }
  // Not removed from under a connection that refers to it: the connection changes or goes first.
  remove(row) {
    const referrers = this.db.prepare('SELECT count(*) n FROM connection_references WHERE secret_id=?').get(row.id).n;
    if (referrers) fail(409, 'secret_in_use', `このシークレットを参照する接続が${referrers}件あります。先にその接続を変えるか削除してください。`, { referrers });
    this.resources.remove(row);
  }
  view(row) { return { ...this.resources.view(row), size: row.size, recipients: this.keys.recipientsOf(row.id) }; }
}
