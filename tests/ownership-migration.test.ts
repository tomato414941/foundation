import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';

test('所有の始まりを、作った時刻と記録に残る最後の受け渡しから埋め、その後は持ち主が変わるたびに記録する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner');
  const team = await f.principals.create('Team', null, owner.actor.id), bot = await f.principals.create('Bot', null, owner.actor.id);
  const item = (name: string) => f.resources.insert(owner.actor.id, 'object', name, { size: 0, contentType: 'text/plain' });
  const kept = await item('kept.txt'), passed = await item('passed.txt'), sealed = await item('sealed.txt');
  await f.relations.transfer(owner.actor, bot.id, team.id);
  await f.relations.transfer(owner.actor, passed.id, team.id);
  // A thing a key protects is passed on by sealing it for its new owner, recorded where each owner keeps its audit.
  await f.db.pool.query('UPDATE resources SET owner_id=$2 WHERE id=$1', [sealed.id, team.id]);
  await f.db.pool.query(`INSERT INTO audit_log(owner_id,actor_id,action,target_id,created_at)
    SELECT v.owner,$1,'resource.protect',x.id,x.created_at+v.after FROM resources x,
      (VALUES ($1::uuid,interval '1 hour'),($2::uuid,interval '2 hours'),($2::uuid,interval '3 hours')) v(owner,after)
    WHERE x.id=$3`, [owner.actor.id, team.id, sealed.id]);
  await f.db.pool.query(`DROP TRIGGER principals_owned_at ON principals; DROP TRIGGER resources_owned_at ON resources;
    DROP FUNCTION stamp_owned_at(); ALTER TABLE principals DROP COLUMN owned_at; ALTER TABLE resources DROP COLUMN owned_at;
    DELETE FROM schema_migrations WHERE name='005-ownership'`);

  await f.db.migrate();
  await f.db.assertReady();
  const owned = async (table: 'principals' | 'resources', id: string) =>
    (await f.db.one<{ owned_at: Date | null }>(`SELECT owned_at FROM ${table} WHERE id=$1`, [id]))!.owned_at?.toISOString() ?? null;
  const recorded = async (action: string, column: 'owner_id' | 'target_id', id: string) =>
    (await f.db.one<{ created_at: Date }>(`SELECT created_at FROM audit_log WHERE action=$1 AND ${column}=$2`, [action, id]))!
      .created_at.toISOString();
  assert.equal(await owned('principals', owner.actor.id), null);
  assert.equal(await owned('principals', team.id), (await f.principals.get(team.id)).created_at.toISOString());
  assert.equal(await owned('principals', bot.id), await recorded('principal.transfer', 'owner_id', bot.id));
  assert.equal(await owned('resources', kept.id), kept.created_at.toISOString());
  assert.equal(await owned('resources', passed.id), await recorded('resource.receive', 'target_id', passed.id));
  assert.equal(await owned('resources', sealed.id), new Date(sealed.created_at.getTime() + 7_200_000).toISOString());

  await f.relations.transfer(owner.actor, kept.id, team.id);
  assert.equal(await owned('resources', kept.id), await recorded('resource.receive', 'target_id', kept.id));
  const device = await f.principals.create('Device', null);
  assert.equal(await owned('principals', device.id), null);
  await f.db.pool.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [device.id, owner.actor.id]);
  assert.notEqual(await owned('principals', device.id), null);
});
