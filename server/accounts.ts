import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import { principal } from './authorization.js';
import type { Context } from './context.js';
import type { ResourceRow } from './resources.js';
import type { SealedItemValue } from '../shared/custody.js';
import { fail } from './errors.js';
import { isProtected } from '../shared/protected.js';
import type { ProtectedKindName } from '../shared/protected.js';

export class Accounts {
  constructor(readonly context: Context) {}
  async *export(actor: Actor, id: string) {
    const c = this.context;
    await c.authorization.requirePrincipal(actor, id, 'export');
    yield JSON.stringify({
      format: 'foundation',
      version: 5,
      exportedAt: new Date().toISOString(),
      principal: await c.principals.view(actor, await c.principals.get(id)),
      mergedIdentities: await c.db.all('SELECT id,name,public_key AS "publicKey",retired_at AS "retiredAt" FROM principals WHERE merged_into=$1 ORDER BY retired_at,id', [id]),
    }) + '\n';
    let after: string | null = null;
    for (;;) {
      const rows: ResourceRow[] = await c.db.all<ResourceRow>(
        'SELECT * FROM resources WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 50',
        [id, after],
      );
      for (const row of rows) {
        const entry: Record<string, unknown> = {
          type: 'resource',
          resource: await c.resources.view(actor, row),
        };
        if (isProtected(row.kind)) {
          const content = await c.db.one<{ content: unknown }>('SELECT content FROM resource_custody WHERE resource_id=$1', [row.id]);
          if (content) entry.custody = content.content;
        }
        if (row.kind === 'object')
          entry.content = Buffer.from(await c.objects.store.get(row.private_data!)).toString('base64');
        yield JSON.stringify(entry) + '\n';
      }
      if (rows.length < 50) break;
      after = rows.at(-1)!.id;
    }
    yield JSON.stringify({
      type: 'relations',
      items: await c.db.all(
        `SELECT subject_id "subjectId",relation,coalesce(principal_id,resource_id) "objectId" FROM relations
        WHERE subject_id=$1 OR principal_id=$1 OR resource_id IN (SELECT id FROM resources WHERE owner_id=$1)`,
        [id],
      ),
    }) + '\n';
    after = null;
    for (;;) {
      const rows: Array<{ id: string }> = await c.db.all('SELECT id FROM requests WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 50', [id, after]);
      for (const row of rows) yield JSON.stringify({ type: 'request', request: await c.requests.get(actor, row.id) }) + '\n';
      if (rows.length < 50) break;
      after = rows.at(-1)!.id;
    }
    after = null;
    for (;;) {
      const rows: Array<{ id: string }> = await c.db.all('SELECT id FROM operations WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 50', [id, after]);
      for (const row of rows) yield JSON.stringify({ type: 'operation', operation: await c.operations.get(actor, row.id) }) + '\n';
      if (rows.length < 50) break;
      after = rows.at(-1)!.id;
    }
    await c.audit.record(id, actor.id, 'principal.export', id);
  }
  async remove(actor: Actor, id: string) {
    const c = this.context;
    await c.authorization.active(actor);
    if (actor.id !== id) await c.authorization.requirePrincipal(actor, id, 'delete');
    const children = await c.db.one('SELECT 1 FROM principals WHERE owner_id=$1 LIMIT 1', [id]);
    if (children) fail(409, 'owned_principals', 'Transfer or delete owned principals first.');
    const rows = await c.db.all<ResourceRow>('SELECT * FROM resources WHERE owner_id=$1', [id]);
    if (rows.some((row) => row.kind === 'connection'))
      fail(409, 'connections_active', 'Disconnect services before deleting this principal.');
    // The database keeps object cleanup jobs after the owning resource is removed.
    await c.db.transaction(async (connection) => {
      await connection.query(
        'DELETE FROM resource_references WHERE resource_id IN (SELECT id FROM resources WHERE owner_id=$1)',
        [id],
      );
      // What it did with others stays in their history, and what still waits there for it ends: the operations it was
      // to make stop, what it asked for is withdrawn, and what it was asked ends unanswered. The requests it kept to
      // itself go with it, while those another principal sent or answered stay, with the operations they made.
      await connection.query(
        "UPDATE operations SET state='cancelled',updated_at=now(),revision=revision+1 WHERE state IN ('stopped','in_progress') AND actor_id=$1",
        [id],
      );
      await connection.query(
        "UPDATE requests SET state=CASE WHEN from_id=$1 THEN 'withdrawn' ELSE 'expired' END,answered_at=now() WHERE state='pending' AND (from_id=$1 OR to_id=$1)",
        [id],
      );
      const shared = 'SELECT id FROM requests WHERE from_id<>$1 OR answered_by<>$1';
      await connection.query(`UPDATE operations SET owner_id=NULL WHERE owner_id=$1 AND request_id IN (${shared})`, [id]);
      await connection.query(`UPDATE requests SET owner_id=NULL WHERE owner_id=$1 AND id IN (${shared})`, [id]);
      await connection.query(
        'DELETE FROM requests WHERE owner_id IS NULL AND from_id=$1 AND (answered_by IS NULL OR answered_by=$1)',
        [id],
      );
      await connection.query('DELETE FROM operations WHERE owner_id IS NULL AND request_id IS NULL AND actor_id=$1', [id]);
      await connection.query('DELETE FROM principals WHERE id=$1', [id]);
    });
  }
  async passkeyProof(actor: Actor, browser: string, input: { challengeId: string; credential: unknown }) {
    const c = this.context,
      proof = await c.authentication.verifyPasskey(browser, input, actor);
    await c.authentication.signout(proof.actor);
    if (proof.principalId === actor.id)
      fail(400, 'same_account', 'Choose a passkey belonging to the other account.');
    const id = randomUUID();
    await c.db.pool.query(
      "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'merge',$2,$3,now()+interval '10 minutes')",
      [id, actor.id, JSON.stringify({ from: proof.principalId, credentialId: proof.credentialId })],
    );
    return { id, fromId: proof.principalId, wrappedKey: proof.wrappedKey, publicKey: proof.publicKey };
  }
  private async proof(actor: Actor, id: string) {
    await this.context.authorization.active(actor);
    const proof = await this.context.db.one<{ data: { from: string; credentialId: string } }>(
      "SELECT data FROM challenges WHERE id=$1 AND kind='merge' AND principal_id=$2 AND expires_at>now()",
      [id, actor.id],
    );
    if (!proof) fail(400, 'invalid_proof', 'Verify the other account again.');
    await this.context.authorization.active({ id: proof.data.from, credentialId: proof.data.credentialId });
    return proof.data;
  }
  async plan(actor: Actor, id: string) {
    const proof = await this.proof(actor, id),
      from = await this.context.principals.get(proof.from),
      resources = await this.context.db.all<ResourceRow>(
        'SELECT * FROM resources WHERE owner_id=$1 ORDER BY created_at',
        [from.id],
      );
    return {
      id,
      from: { id: from.id, name: from.name, publicKey: from.public_key },
      resources: await Promise.all(resources.map((row) => this.context.resources.view({ id: from.id }, row))),
      protectedItems: [...await Promise.all(resources.filter(row => isProtected(row.kind))
        .map(async row => ({ id: row.id, kind: row.kind as ProtectedKindName, version: row.version,
          content: await this.context.custody.get(row.id) })))],
      // What the other account holds passes to this one, sealed for whoever uses what this one holds.
      recipients: await this.context.custody.ownerRecipients(actor.id),
    };
  }
  async merge(actor: Actor, id: string, contents: Record<string, { version: number; content: SealedItemValue }>) {
    const c = this.context,
      proof = await this.proof(actor, id),
      from = await c.principals.get(proof.from),
      to = await c.principals.get(actor.id);
    await c.authorization.active({ id: from.id });
    if (
      await c.db.one(
        `SELECT 1 FROM principals WHERE id=ANY($1::uuid[]) AND owner_id IS NOT NULL
        UNION ALL SELECT 1 FROM relations WHERE principal_id=ANY($1::uuid[]) AND relation='member' LIMIT 1`,
        [[from.id, to.id]],
      )
    )
      fail(
        409,
        'managed_accounts',
        'Merge personal accounts that are not owned or managed by another principal.',
      );
    if ((await c.authorization.holds(from.id, principal(to.id), 'stands')) || (await c.authorization.holds(to.id, principal(from.id), 'stands')))
      fail(409, 'related_accounts', 'These principals are already connected by ownership or membership.');
    const rows = await c.db.all<ResourceRow>('SELECT * FROM resources WHERE owner_id=$1', [from.id]);
    const children = await c.db.one('SELECT 1 FROM principals WHERE owner_id=$1 LIMIT 1', [from.id]);
    if (children) fail(409, 'owned_principals', 'Transfer owned principals before merging accounts.');
    for (const row of rows.filter(row => isProtected(row.kind))) {
      const update = contents[row.id];
      if (!update || update.version !== row.version)
        fail(409, 'rekey_required', 'Unlock both accounts and seal protected items for the new owner.');
    }
    await c.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const consumed = await connection.query(
        "DELETE FROM challenges WHERE id=$1 AND principal_id=$2 AND kind='merge' AND expires_at>now()",
        [id, to.id],
      );
      if (!consumed.rowCount) fail(400, 'invalid_proof', 'Verify the other account again.');
      await connection.query('SELECT id FROM principals WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE', [
        [from.id, to.id],
      ]);
      for (const row of rows) {
        let name = row.name;
        if (
          await c.db.one(
            'SELECT 1 FROM resources WHERE owner_id=$1 AND kind=$2 AND name=$3',
            [to.id, row.kind, name],
            connection,
          )
        )
          name = name.slice(0, 150) + ' · ' + row.id;
        if (isProtected(row.kind)) {
          // Both accounts are this person's: the one merged into agrees to receive what the other passes on.
          await c.custody.transfer({ id: from.id, credentialId: proof.credentialId, agreedBy: to.id }, to.id,
            { ...contents[row.id]!, id: row.id, name, kind: row.kind, ownerId: to.id }, connection);
        } else {
          await c.resources.changeOwner(row, to.id, connection, name);
        }
      }
      // The lines the other account was given, and those drawn onto it, become this account's.
      const lines = await c.db.all<{ subject_id: string; relation: string; principal_id: string | null; resource_id: string | null }>(
        'SELECT subject_id,relation,principal_id,resource_id FROM relations WHERE subject_id=$1 OR principal_id=$1',
        [from.id],
        connection,
      );
      await connection.query('DELETE FROM relations WHERE subject_id=$1 OR principal_id=$1', [from.id]);
      for (const line of lines) {
        const subject = line.subject_id === from.id ? to.id : line.subject_id,
          target = line.principal_id === from.id ? to.id : line.principal_id;
        if (subject !== target)
          await connection.query(
            'INSERT INTO relations(subject_id,relation,principal_id,resource_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',
            [subject, line.relation, target, line.resource_id],
          );
      }
      // What either made stays with the one they become; what is still to be made or answered ends.
      await connection.query(
        `UPDATE operations SET state=CASE WHEN state IN ('stopped','in_progress') THEN 'cancelled' ELSE state END,
        owner_id=CASE WHEN owner_id=$1 THEN $2 ELSE owner_id END,revision=revision+1,updated_at=now() WHERE owner_id=$1 OR actor_id=$1`,
        [from.id, to.id],
      );
      await connection.query(`UPDATE requests SET to_id=CASE WHEN to_id=$1 THEN $2 ELSE to_id END,
        owner_id=CASE WHEN owner_id=$1 THEN $2 ELSE owner_id END,answered_by=CASE WHEN answered_by=$1 THEN $2 ELSE answered_by END,
        state=CASE WHEN state='pending' AND from_id=$1 THEN 'withdrawn' WHEN state='pending' THEN 'expired' ELSE state END,
        answered_at=CASE WHEN state='pending' THEN now() ELSE answered_at END WHERE from_id=$1 OR to_id=$1 OR owner_id=$1 OR answered_by=$1`, [from.id, to.id]);
      await connection.query(
        "UPDATE credentials SET principal_id=$2,private_wrap=NULL,data=CASE WHEN kind='key' AND NOT data ? 'publicKey' THEN data||jsonb_build_object('publicKey',$3::jsonb) ELSE data END WHERE principal_id=$1",
        [from.id, to.id, JSON.stringify(from.public_key)],
      );
      await connection.query('DELETE FROM sessions WHERE principal_id=$1', [from.id]);
      await connection.query('UPDATE audit_log SET owner_id=$2 WHERE owner_id=$1', [from.id, to.id]);
      // Keep the source identity for signed records and immutable authorship, without allowing it to act again.
      await connection.query('DELETE FROM challenges WHERE principal_id=$1', [from.id]);
      await connection.query('UPDATE principals SET merged_into=$2 WHERE merged_into=$1', [from.id, to.id]);
      await connection.query('UPDATE principals SET retired_at=now(),merged_into=$2 WHERE id=$1', [from.id, to.id]);
      await c.audit.record(to.id, to.id, 'principal.merge', to.id, { from: from.id }, connection);
    });
    return c.principals.view(actor, await c.principals.get(to.id));
  }
}
