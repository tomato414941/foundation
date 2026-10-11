import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';

test('既存環境の移行が済むまで起動を止め、ディスクと接続先の情報を保持する', async t => {
  const f = await fixture(), owner = await f.person();
  t.after(f.close);
  const row = await f.resources.insert(owner.actor.id, 'environment', 'Existing environment', { driver: 'managed', state: 'stopped' });
  await f.db.pool.query('ALTER TABLE environment_jobs DROP COLUMN provider');
  await f.db.pool.query('ALTER TABLE environment_jobs ADD COLUMN ssh_port integer');
  await f.db.pool.query('INSERT INTO environment_jobs(resource_id,machine_id,volume_id,ssh_port) VALUES($1,$2,$3,$4)',
    [row.id, 'existing-machine', 'existing-disk', 24000]);
  await assert.rejects(createContext(f.config, { db: f.db }), /Migrate existing managed environment disks/);
  assert.deepEqual(await f.db.one('SELECT machine_id,volume_id,ssh_port FROM environment_jobs WHERE resource_id=$1', [row.id]),
    { machine_id: 'existing-machine', volume_id: 'existing-disk', ssh_port: 24000 });
  assert.equal((await f.resources.get(row.id)).name, 'Existing environment');
});
