import { randomUUID } from 'node:crypto';
import type { Actor } from './authorization.js';
import type { Context } from './context.js';
import type { ResourceRow } from './resources.js';
import type { SealedContent } from '../shared/contracts.js';
import { Sealed } from '../shared/contracts.js';
import { encode } from '../shared/encryption.js';
import { fail } from './errors.js';

export class Accounts {
  constructor(readonly context: Context) {}
  async *export(actor: Actor, id: string) {
    const c = this.context;
    await c.authorization.requirePrincipal(actor, id, 'export');
    const recipient = await c.principals.get(actor.id);
    if (!recipient.public_key)
      fail(409, 'encryption_key_required', 'Add an encryption key before exporting private data.');
    yield JSON.stringify({
      format: 'foundation',
      version: 1,
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
        if (row.kind === 'secret') entry.sealed = row.sealed;
        if (row.kind === 'object')
          entry.content = Buffer.from(await c.objects.store.get(row.private_data!)).toString('base64');
        if (['app', 'connection'].includes(row.kind) && row.private_data) {
          const privateData = await c.vault.decrypt<unknown>(row.private_data, 'resource:' + row.id),
            context = 'export:' + row.id;
          entry.private = {
            context,
            sealed: await c.identity.seal(
              encode(JSON.stringify(privateData)),
              [{ id: actor.id, publicKey: recipient.public_key }],
              context,
            ),
          };
        }
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
    if (id === c.identity.id || actor.requestId) fail(403, 'forbidden', 'This principal cannot be removed.');
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
      secrets: resources
        .filter((row) => row.kind === 'secret')
        .map((row) => ({ id: row.id, sealed: row.sealed! })),
      recipients: await this.context.resources.recipients(actor.id),
    };
  }
  async merge(actor: Actor, id: string, secrets: Record<string, SealedContent>) {
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
    const recipients = await c.resources.recipients(to.id),
      envelopes = new Map<string, SealedContent>();
    for (const row of rows.filter((row) => row.kind === 'secret')) {
      let sealed = secrets[row.id];
      const allowUse = await c.authorization.resource({ id: c.identity.id }, row, 'use');
      if (!sealed && allowUse) {
        const addressed = [
          ...recipients,
          { id: c.identity.id, name: 'Foundation', publicKey: c.identity.publicKey },
        ].filter((value, index, all) => all.findIndex((other) => other.id === value.id) === index);
        sealed = await c.identity.seal(
          await c.identity.open(row.sealed, 'resource:' + row.id),
          addressed,
          'resource:' + row.id,
        );
      }
      if (!sealed) fail(409, 'encryption_access', 'Unlock the other account to merge its secrets.');
      await c.resources.validateSecret(to.id, row.id, sealed, allowUse);
      envelopes.set(row.id, Sealed.parse(sealed));
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
        const sealed = envelopes.get(row.id) ?? row.sealed;
        if (row.kind === 'secret' && sealed)
          await c.resources.validateSecret(to.id, row.id, sealed,
            await c.authorization.resource({ id: c.identity.id }, row, 'use', connection), connection);
        const data =
          sealed && row.kind === 'secret'
            ? { ...row.data, recipients: sealed.recipients.map((value) => value.header.kid) }
            : row.data;
        const changed = await connection.query(
          'UPDATE resources SET owner_id=$3,name=$4,sealed=$5,data=$6,version=version+1,updated_at=now() WHERE id=$1 AND version=$2',
          [row.id, row.version, to.id, name, JSON.stringify(sealed), JSON.stringify(data)],
        );
        if (!changed.rowCount) fail(409, 'changed', 'An item changed while merging. Start again.');
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
      await connection.query('UPDATE runs SET owner_id=$2 WHERE owner_id=$1', [from.id, to.id]);
      await connection.query('UPDATE runs SET actor_id=$2 WHERE actor_id=$1', [from.id, to.id]);
      await connection.query('UPDATE audit_log SET owner_id=$2 WHERE owner_id=$1', [from.id, to.id]);
      await connection.query('UPDATE audit_log SET actor_id=$2 WHERE actor_id=$1', [from.id, to.id]);
      await connection.query('DELETE FROM principals WHERE id=$1', [from.id]);
      await c.audit.record(to.id, to.id, 'principal.merge', to.id, { from: from.id }, connection);
    });
    return c.principals.view(actor, await c.principals.get(to.id));
  }
}
