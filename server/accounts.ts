import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Context } from './context.js';
import type { ResourceRow } from './resources.js';
import type { CustodyContent } from '../shared/custody.js';
import { fail } from './errors.js';
import { isProtected } from '../shared/protected.js';

export class Accounts {
  constructor(readonly context: Context) {}
  async *export(actor: Actor, id: string) {
    const c = this.context;
    await c.authorization.requirePrincipal(actor, id, 'export');
    yield JSON.stringify({
      format: 'foundation',
      version: 2,
      exportedAt: new Date().toISOString(),
      principal: await c.principals.view(actor, await c.principals.get(id)),
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
          else entry.encryptedStorage = { sealed: row.sealed, privateData: row.private_data };
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
        'SELECT subject_id,principal_id,relation FROM relations WHERE subject_id=$1 OR principal_id=$1',
        [id],
      ),
    }) + '\n';
    await c.audit.record(id, actor.id, 'principal.export', id);
  }
  async remove(actor: Actor, id: string) {
    const c = this.context;
    await c.authorization.active(actor);
    if (actor.requestId) fail(403, 'forbidden', 'This principal cannot be removed.');
    if (actor.id !== id) await c.authorization.requirePrincipal(actor, id, 'delete');
    const account = await c.db.one<{ status: string }>(
      'SELECT status FROM payment_accounts WHERE principal_id=$1',
      [id],
    );
    if (account && ['active', 'trialing', 'past_due', 'unpaid'].includes(account.status))
      fail(409, 'subscription_active', 'Cancel the subscription before deleting this principal.');
    const children = await c.db.one(
      "SELECT 1 FROM relations WHERE subject_id=$1 AND relation='owner' LIMIT 1",
      [id],
    );
    if (children) fail(409, 'owned_principals', 'Transfer or delete owned principals first.');
    const rows = await c.db.all<ResourceRow>('SELECT * FROM resources WHERE owner_id=$1', [id]);
    if (rows.some((row) => row.kind === 'connection'))
      fail(409, 'connections_active', 'Disconnect services before deleting this principal.');
    if (
      rows.some(
        (row) => row.kind === 'environment' && !['stopped', 'failed'].includes(String(row.data.state)),
      )
    )
      fail(409, 'environment_active', 'Stop all environments before deleting this principal.');
    // The database keeps object cleanup jobs after the owning resource is removed.
    await c.db.transaction(async (connection) => {
      await connection.query(
        'DELETE FROM resource_references WHERE resource_id IN (SELECT id FROM resources WHERE owner_id=$1)',
        [id],
      );
      await connection.query('DELETE FROM principals WHERE id=$1', [id]);
    });
  }
  async passkeyProof(actor: Actor, browser: string, input: { challengeId: string; credential: unknown }) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to merge accounts.');
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
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to merge accounts.');
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
      protectedItems: await Promise.all(resources.filter(row => isProtected(row.kind))
        .map(async row => ({ id: row.id, version: row.version, content: await this.context.custody.get(row.id) }))),
      recipients: await this.context.custody.recipients(actor.id),
    };
  }
  async merge(actor: Actor, id: string, contents: Record<string, { version: number; content: CustodyContent }>) {
    const c = this.context,
      proof = await this.proof(actor, id),
      from = await c.principals.get(proof.from),
      to = await c.principals.get(actor.id);
    if (
      await c.db.one(
        "SELECT 1 FROM relations WHERE principal_id=ANY($1::uuid[]) AND relation IN ('owner','member') LIMIT 1",
        [[from.id, to.id]],
      )
    )
      fail(
        409,
        'managed_accounts',
        'Merge personal accounts that are not owned or managed by another principal.',
      );
    if ((await c.authorization.stands(from.id, to.id)) || (await c.authorization.stands(to.id, from.id)))
      fail(409, 'related_accounts', 'These principals are already connected by ownership or membership.');
    const accounts = await c.db.all<{ principal_id: string; status: string }>(
      'SELECT principal_id,status FROM payment_accounts WHERE principal_id=ANY($1::uuid[])',
      [[from.id, to.id]],
    );
    if (accounts.length > 1)
      fail(409, 'payment_accounts', 'Keep the payment account on one principal before merging.');
    const rows = await c.db.all<ResourceRow>('SELECT * FROM resources WHERE owner_id=$1', [from.id]);
    if (
      rows.some(
        (row) => row.kind === 'environment' && !['stopped', 'failed'].includes(String(row.data.state)),
      )
    )
      fail(409, 'environment_active', 'Stop environments on the other account before merging.');
    const externalKeys = await c.db.one(
      `SELECT 1 FROM resource_custody c JOIN resources r ON r.id=c.resource_id
       WHERE r.owner_id<>$1 AND jsonb_path_exists(c.content,
         '$.policy.**.principalId ? (@ == $principal)',jsonb_build_object('principal',$1::text)) LIMIT 1`, [from.id]);
    if (externalKeys) fail(409, 'rekey_required', 'Ask other resource owners to replace the previous account keys before merging.');
    const children = await c.db.one("SELECT 1 FROM relations WHERE subject_id=$1 AND relation='owner' LIMIT 1", [from.id]);
    if (children) fail(409, 'owned_principals', 'Transfer owned principals before merging accounts.');
    if (await c.db.one("SELECT 1 FROM execution_tasks WHERE (owner_id=$1 OR actor_id=$1) AND state IN ('queued','running','uncertain') LIMIT 1", [from.id]))
      fail(409, 'execution_active', 'Resolve active executions before merging accounts.');
    for (const row of rows.filter(row => isProtected(row.kind))) {
      const update = contents[row.id];
      if (!update || update.version !== row.version || update.content.policy.ownerId !== to.id)
        fail(409, 'rekey_required', 'Unlock both accounts and re-encrypt protected items for the new owner.');
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
          await c.custody.put({ id: from.id, credentialId: proof.credentialId }, { ...contents[row.id]!, name }, connection);
        } else {
          const changed = await connection.query(
            'UPDATE resources SET owner_id=$3,name=$4,version=version+1,updated_at=now() WHERE id=$1 AND version=$2',
            [row.id, row.version, to.id, name]);
          if (!changed.rowCount) fail(409, 'changed', 'An item changed while merging. Start again.');
        }
      }
      const relations = await c.db.all<{ subject_id: string; principal_id: string; relation: string }>(
        'SELECT subject_id,principal_id,relation FROM relations WHERE subject_id=$1 OR principal_id=$1',
        [from.id],
        connection,
      );
      await connection.query('DELETE FROM relations WHERE subject_id=$1 OR principal_id=$1', [from.id]);
      for (const relation of relations) {
        const subject = relation.subject_id === from.id ? to.id : relation.subject_id,
          target = relation.principal_id === from.id ? to.id : relation.principal_id;
        if (subject !== target)
          await connection.query(
            'INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',
            [randomUUID(), subject, target, relation.relation],
          );
      }
      const grants = await c.db.all<{ resource_id: string; actions: string[] }>(
        'SELECT resource_id,actions FROM grants WHERE principal_id=$1',
        [from.id],
        connection,
      );
      for (const grant of grants)
        await connection.query(
          'INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,$3) ON CONFLICT(resource_id,principal_id) DO UPDATE SET actions=ARRAY(SELECT DISTINCT unnest(grants.actions||EXCLUDED.actions))',
          [grant.resource_id, to.id, grant.actions],
        );
      const principalGrants = await c.db.all<{ target_id: string; principal_id: string; actions: string[] }>(
        'SELECT * FROM principal_grants WHERE target_id=$1 OR principal_id=$1',
        [from.id],
        connection,
      );
      await connection.query('DELETE FROM principal_grants WHERE target_id=$1 OR principal_id=$1', [from.id]);
      for (const grant of principalGrants)
        await connection.query(
          'INSERT INTO principal_grants(target_id,principal_id,actions) VALUES($1,$2,$3) ON CONFLICT(target_id,principal_id) DO UPDATE SET actions=ARRAY(SELECT DISTINCT unnest(principal_grants.actions||EXCLUDED.actions))',
          [
            grant.target_id === from.id ? to.id : grant.target_id,
            grant.principal_id === from.id ? to.id : grant.principal_id,
            grant.actions,
          ],
        );
      await connection.query(
        "UPDATE approval_requests SET state=CASE WHEN state IN ('pending','running') THEN 'cancelled' ELSE state END,private_input=NULL,continue_url=NULL,from_id=CASE WHEN from_id=$1 THEN $2 ELSE from_id END,to_id=CASE WHEN to_id=$1 THEN $2 ELSE to_id END WHERE from_id=$1 OR to_id=$1",
        [from.id, to.id],
      );
      await connection.query(
        "UPDATE credentials SET principal_id=$2,private_wrap=NULL,data=CASE WHEN kind='key' AND NOT data ? 'publicKey' THEN data||jsonb_build_object('publicKey',$3::jsonb) ELSE data END WHERE principal_id=$1",
        [from.id, to.id, JSON.stringify(from.public_key)],
      );
      await connection.query('DELETE FROM sessions WHERE principal_id=$1', [from.id]);
      await connection.query('UPDATE payment_accounts SET principal_id=$2 WHERE principal_id=$1', [
        from.id,
        to.id,
      ]);
      await connection.query('UPDATE billing_events SET payer_id=$2 WHERE payer_id=$1', [from.id, to.id]);
      await connection.query('UPDATE billing_events SET principal_id=$2 WHERE principal_id=$1', [
        from.id,
        to.id,
      ]);
      await connection.query('UPDATE execution_tasks SET owner_id=$2 WHERE owner_id=$1', [from.id, to.id]);
      await connection.query('UPDATE execution_tasks SET actor_id=$2 WHERE actor_id=$1', [from.id, to.id]);
      await connection.query('UPDATE audit_log SET owner_id=$2 WHERE owner_id=$1', [from.id, to.id]);
      await connection.query('UPDATE audit_log SET actor_id=$2 WHERE actor_id=$1', [from.id, to.id]);
      await connection.query('DELETE FROM principals WHERE id=$1', [from.id]);
      await c.audit.record(to.id, to.id, 'principal.merge', to.id, { from: from.id }, connection);
    });
    return c.principals.view(actor, await c.principals.get(to.id));
  }
}
