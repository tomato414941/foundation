import { randomUUID } from 'node:crypto';

// The addresses a principal has shown it receives email at: one of its entries, beside its passkeys and keys. An
// address belongs to one principal; reaching it is one way to prove being that principal, weaker than a key's signature.
export class Emails {
  constructor(store) { this.db = store.db; }
  principalOf(address) { return this.db.prepare('SELECT principal_id FROM emails WHERE address=?').get(address)?.principal_id; }
  // In the order they were first proven.
  of(principalId) { return this.list(principalId).map(row => row.address); }
  list(principalId) { return this.db.prepare('SELECT id, address, principal_id, created_at FROM emails WHERE principal_id=? ORDER BY rowid').all(principalId); }
  get(id) { return typeof id === 'string' ? this.db.prepare('SELECT id, address, principal_id, created_at FROM emails WHERE id=?').get(id) : undefined; }
  add(principalId, address) { this.db.prepare('INSERT OR IGNORE INTO emails (address,principal_id,id,created_at) VALUES (?,?,?,?)').run(address, principalId, randomUUID(), Date.now()); }
  // Taking an address away ends the sessions it proved.
  remove(row) {
    this.db.prepare("DELETE FROM sessions WHERE proof='email' AND proof_ref=?").run(row.address);
    this.db.prepare('DELETE FROM emails WHERE id=?').run(row.id);
  }
}
