import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';

test('所有の始まりを、作ったときと持ち主が変わるたびに記録する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner');
  const team = await f.principals.create('Team', null, owner.actor.id);
  const owned = async (table: 'principals' | 'resources', id: string) =>
    (await f.db.one<{ owned_at: Date | null }>(`SELECT owned_at FROM ${table} WHERE id=$1`, [id]))!.owned_at?.toISOString() ?? null;
  const recorded = async (id: string) => (await f.db.one<{ created_at: Date }>(
    "SELECT created_at FROM audit_log WHERE action='resource.receive' AND target_id=$1", [id]))!.created_at.toISOString();
  const kept = await f.resources.insert(owner.actor.id, 'object', 'kept.txt', { size: 0, contentType: 'text/plain' });
  assert.equal(await owned('resources', kept.id), kept.created_at.toISOString());
  assert.equal(await owned('principals', owner.actor.id), null);
  assert.equal(await owned('principals', team.id), (await f.principals.get(team.id)).created_at.toISOString());
  await f.relations.transfer(owner.actor, kept.id, team.id);
  assert.equal(await owned('resources', kept.id), await recorded(kept.id));
  const device = await f.principals.create('Device', null);
  assert.equal(await owned('principals', device.id), null);
  await f.db.pool.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [device.id, owner.actor.id]);
  assert.notEqual(await owned('principals', device.id), null);
});
