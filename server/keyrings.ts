import type { z } from 'zod';
import type { Database, Queryable } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Audit } from './audit.js';
import type { Bindings } from './bindings.js';
import type { ResourceRow, Resources } from './resources.js';
import { fail } from './errors.js';
import { openKeyring } from '../shared/keyring.js';
import type { KeyringWrite } from '../shared/keyring.js';

// The list of public keys a principal verified, kept as its resource. The server checks the writer's signature and that
// each revision follows the last, but the principal's devices check the list again before using it.
export class Keyrings {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit,
    readonly resources: Resources, readonly bindings: Bindings, readonly origin: string) {}
  private row(ownerId: string, connection: Queryable = this.db.pool) {
    return this.db.one<ResourceRow>("SELECT * FROM resources WHERE owner_id=$1 AND kind='keyring'", [ownerId], connection);
  }
  async get(actor: Actor, ownerId: string) {
    const row = await this.row(ownerId);
    if (row) await this.authorization.requireResource(actor, row, 'read');
    else await this.authorization.requirePrincipal(actor, ownerId, 'use');
    return { keyring: row ? { version: row.version, signature: String(row.data.signature) } : null };
  }
  async put(actor: Actor, ownerId: string, input: z.infer<typeof KeyringWrite>) {
    const { binding } = await this.bindings.current(actor.id);
    const keyring = await openKeyring(input.signature, binding)
      .catch(() => fail(400, 'invalid_keyring', 'Sign the list of verified public keys with your current keys.'));
    if (keyring.ownerId !== ownerId || keyring.origin !== this.origin)
      fail(400, 'invalid_keyring', 'Sign the list of verified public keys for this principal on this Foundation server.');
    return this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [ownerId]);
      const row = await this.row(ownerId, connection);
      if (row) await this.authorization.requireResource(actor, row, 'update', connection);
      else if (!(await this.authorization.canCreate(actor, ownerId, 'keyring', connection)))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      if ((row?.version ?? null) !== input.version || keyring.revision !== (row ? Number(row.data.revision) : 0) + 1)
        fail(409, 'changed', 'This item changed. Reload it before saving.');
      const data = { revision: keyring.revision, signature: input.signature };
      const saved = row ? await this.resources.update(row, { data }, connection)
        : await this.resources.insert(ownerId, 'keyring', 'Verified public keys', data, {}, connection);
      await this.audit.record(ownerId, actor.id, 'keyring.update', saved.id, { revision: keyring.revision }, connection);
      return { keyring: { version: saved.version, signature: input.signature } };
    });
  }
}
