// The addresses a principal has shown it receives email at. An address belongs to one principal; reaching it is one
// way to prove being that principal, weaker than a key's signature.
export class Emails {
  constructor(store) { this.db = store.db; }
  principalOf(address) { return this.db.prepare('SELECT principal_id FROM emails WHERE address=?').get(address)?.principal_id; }
  // In the order they were first proven.
  of(principalId) { return this.db.prepare('SELECT address FROM emails WHERE principal_id=? ORDER BY rowid').all(principalId).map(row => row.address); }
  add(principalId, address) { this.db.prepare('INSERT OR IGNORE INTO emails (address,principal_id) VALUES (?,?)').run(address, principalId); }
}
