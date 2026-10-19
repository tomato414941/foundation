import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Vault } from '../server/vault.js';
import { migrateDelegates } from '../server/migrations/migrate-delegates.js';
import { RequestInput } from '../shared/contracts.js';
import type { RequestedOperation } from '../shared/contracts.js';

test('保存済みの関係と依頼を委任先へ移行し、同じ権限でリソースを操作して委任を解除する', async t => {
  const f = await fixture(), c = await createContext(f.config, { db: f.db, mailer: f.mailer }), app = await buildApp(c);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), delegate = await f.person('Delegate'), requester = await f.person('Requester');
  const line = { subjectId: delegate.actor.id, relation: 'delegate', objectId: owner.actor.id };
  const completed = await c.executions.start(owner.actor, [{ name: 'relation.draw', input: line }]);
  const item = await c.resources.insert(owner.actor.id, 'object', 'agent-notes.txt', { size: 0, contentType: 'text/plain' });
  const asked = await c.requests.create(requester.actor, RequestInput.parse({ to: owner.actor.id, message: 'agent', operations: [{
    name: 'relation.draw', input: { subjectId: requester.actor.id, relation: 'delegate', objectId: owner.actor.id },
  }] }));
  const before = await c.relations.list(owner.actor, { object: owner.actor.id, relation: 'delegate', limit: 100 });
  const snapshots = await c.db.all<{ id: string; snapshot: string }>('SELECT id,snapshot FROM executions');
  await c.db.transaction(async connection => {
    await connection.query("UPDATE relations SET relation='agent' WHERE relation='delegate'");
    await connection.query("UPDATE audit_log SET details=jsonb_set(details,'{relation}','\"agent\"'::jsonb) WHERE details->>'relation'='delegate'");
    await connection.query('UPDATE executions SET proposal=$2 WHERE id=$1', [asked.executionId,
      { kind: 'line', subjectId: requester.actor.id, relation: 'agent', objectId: owner.actor.id }]);
    for (const row of snapshots) {
      const snapshot = await c.vault.decrypt<{ operations: RequestedOperation[] }>(row.snapshot, 'operation-execution:' + row.id);
      for (const operation of snapshot.operations) if (operation.input.relation === 'delegate') operation.input.relation = 'agent';
      await connection.query('UPDATE executions SET snapshot=$2 WHERE id=$1', [row.id,
        await c.vault.encrypt(snapshot, 'operation-execution:' + row.id)]);
    }
    await connection.query("DELETE FROM schema_migrations WHERE name='006-delegates'");
  });

  await assert.rejects(migrateDelegates(c.db, new Vault(randomBytes(32))));
  await createContext(f.config, { db: c.db, mailer: f.mailer }, { migrate: true });
  await migrateDelegates(c.db, c.vault);
  await c.db.assertReady();
  const listed = await app.inject({ url: '/api/relations?object=' + owner.actor.id + '&relation=delegate',
    headers: { authorization: 'Bearer ' + owner.token } });
  assert.equal(listed.statusCode, 200, listed.body);
  assert.deepEqual(listed.json().items, before.items);
  const resource = await app.inject({ url: '/api/resources/' + item.id,
    headers: { authorization: 'Bearer ' + delegate.token } });
  assert.equal(resource.statusCode, 200, resource.body);
  assert.equal(resource.json().name, 'agent-notes.txt');
  assert.ok(resource.json().permissions.includes('update') && resource.json().permissions.includes('delete'));
  const history = await c.executions.get(owner.actor, completed.id);
  assert.equal(history.operations[0]?.input.relation, 'delegate');
  assert.equal(history.state, 'succeeded');
  assert.ok((await c.audit.list(owner.actor.id)).items.some(entry => entry.action === 'relation.add' && entry.details.relation === 'delegate'));
  const request = await c.requests.get(owner.actor, asked.id);
  assert.equal(request.message, 'agent');
  assert.equal(request.url, asked.url);
  const pending = await c.executions.get(owner.actor, asked.executionId);
  assert.equal(pending.operations[0]?.input.relation, 'delegate');
  assert.equal(pending.approval?.proposal?.kind === 'line' && pending.approval.proposal.relation, 'delegate');
  await c.requests.approve(owner.actor, asked.id, []);
  assert.equal(await c.authorization.holds(requester.actor.id, item, 'update'), true);
  await c.relations.erase(owner.actor, line);
  assert.equal(await c.authorization.holds(delegate.actor.id, item, 'read'), false);
});
