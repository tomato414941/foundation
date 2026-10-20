import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';

test('既存のDBを移行し、持ち主の記録に実行者として残るプリンシパルを削除して、その記録を残す', async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const accounts = new Accounts(await createContext(f.config, { db: f.db, mailer: f.mailer }));
  const owner = await f.person('Owner'), agent = await f.person('Agent');
  // Databases made earlier tie these records to the principals named in them, some under the names of earlier tables.
  await f.db.pool.query(`
    ALTER TABLE execution_tasks ADD CONSTRAINT execution_tasks_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id);
    ALTER TABLE environment_processes
      ADD CONSTRAINT environment_processes_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id),
      ADD CONSTRAINT environment_processes_executor_id_fkey FOREIGN KEY (executor_id) REFERENCES principals(id);
    ALTER TABLE function_invocations
      ADD CONSTRAINT function_invocations_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id) ON DELETE CASCADE,
      ADD CONSTRAINT function_invocations_executor_id_fkey FOREIGN KEY (executor_id) REFERENCES principals(id);
    ALTER TABLE connection_operations
      ADD CONSTRAINT connection_operations_executor_id_fkey FOREIGN KEY (executor_id) REFERENCES principals(id);
    ALTER TABLE executions
      ADD CONSTRAINT operation_executions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id) ON DELETE CASCADE,
      ADD CONSTRAINT operation_executions_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES principals(id) ON DELETE CASCADE,
      ADD CONSTRAINT operation_executions_responder_id_fkey FOREIGN KEY (responder_id) REFERENCES principals(id) ON DELETE CASCADE;
    ALTER TABLE requests
      ADD CONSTRAINT requests_from_id_fkey FOREIGN KEY (from_id) REFERENCES principals(id) ON DELETE CASCADE,
      ADD CONSTRAINT requests_to_id_fkey FOREIGN KEY (to_id) REFERENCES principals(id) ON DELETE CASCADE;
    ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id) ON DELETE SET NULL;
    ALTER TABLE environment_deletions
      ADD CONSTRAINT environment_deletions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES principals(id) ON DELETE SET NULL;
    ALTER TABLE billing_events
      ADD CONSTRAINT billing_events_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE;
    DELETE FROM schema_migrations WHERE name='007-principal-history'`);
  // The agent ran a command for the owner, left a renewal of the owner's connection unresolved, changed an item, deleted
  // an environment of the owner's and used compute the owner pays for.
  const task = randomUUID(), operation = randomUUID(), execution = randomUUID(), environment = randomUUID(), usage = randomUUID();
  const item = await f.resources.insert(owner.actor.id, 'object', 'kept.txt', { size: 0, contentType: 'text/plain' });
  await f.db.pool.query(`INSERT INTO execution_tasks(id,owner_id,actor_id,environment_id,kind,state,actor,request)
    VALUES($1,$2,$3,$4,'command','succeeded','{}','{}')`, [task, owner.actor.id, agent.actor.id, randomUUID()]);
  await f.db.pool.query(`INSERT INTO connection_operations(id,resource_id,executor_id,expected_revision,state)
    VALUES($1,$2,$3,1,'uncertain')`, [operation, item.id, agent.actor.id]);
  await f.db.pool.query(`INSERT INTO executions(id,actor_id,creator_id,owner_id,state,snapshot,expires_at)
    VALUES($1,$2,$2,$3,'succeeded','',now()+interval '1 day')`, [execution, agent.actor.id, owner.actor.id]);
  await f.db.pool.query(`INSERT INTO audit_log(owner_id,actor_id,action,target_id) VALUES($1,$2,'resource.protect',$3)`,
    [owner.actor.id, agent.actor.id, item.id]);
  await f.db.pool.query(`INSERT INTO environment_deletions(resource_id,owner_id,actor_id,state) VALUES($1,$2,$3,'complete')`,
    [environment, owner.actor.id, agent.actor.id]);
  await f.db.pool.query(`INSERT INTO billing_events(id,reference,payer_id,principal_id,meter,amount) VALUES($1,$2,$3,$4,'compute',35)`,
    [usage, 'compute:' + usage, owner.actor.id, agent.actor.id]);

  await f.db.migrate();
  await f.db.assertReady();
  await accounts.remove(agent.actor, agent.actor.id);
  assert.equal(await f.db.one('SELECT 1 FROM principals WHERE id=$1', [agent.actor.id]), undefined);
  const named = async (sql: string, id: string) => (await f.db.one<{ actor: string }>(sql, [id]))?.actor;
  assert.equal(await named('SELECT actor_id AS actor FROM execution_tasks WHERE id=$1', task), agent.actor.id);
  assert.equal(await named("SELECT executor_id AS actor FROM connection_operations WHERE id=$1 AND state='uncertain'", operation),
    agent.actor.id);
  assert.equal(await named('SELECT creator_id AS actor FROM executions WHERE id=$1', execution), agent.actor.id);
  assert.equal(await named("SELECT actor_id AS actor FROM audit_log WHERE action='resource.protect' AND target_id=$1", item.id),
    agent.actor.id);
  assert.equal(await named('SELECT actor_id AS actor FROM environment_deletions WHERE resource_id=$1', environment), agent.actor.id);
  assert.equal(await named('SELECT principal_id AS actor FROM billing_events WHERE id=$1', usage), agent.actor.id);
});
