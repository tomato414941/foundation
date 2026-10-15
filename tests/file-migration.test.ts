import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryFiles } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Vault } from '../server/vault.js';
import { migrateFiles } from '../server/migrations/migrate-files.js';
import { FileResource, Principal, RequestInput } from '../shared/contracts.js';

test('保存済みのファイルと共有権限と依頼を移行し、同じIDで内容を読み更新する', async t => {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included' }), storage = new MemoryFiles();
  const c = await createContext(f.config, { db: f.db, storage }), app = await buildApp(c);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('File owner'), reader = await f.person('Reader'), sender = await f.person('Requester');
  const original = Buffer.from('{"kind":"object","name":"object.create"}');
  const completed = await c.executions.start(owner.actor, [{ name: 'file.create', input: {
    ownerId: owner.actor.id, name: 'note.txt', bytes: original.toString('base64url'), contentType: 'text/plain',
  } }]);
  const file = FileResource.parse(completed.results[0]), row = await c.resources.get(file.id);
  for (const relation of ['reader', 'user']) await c.relations.draw(owner.actor, {
    subjectId: reader.actor.id, relation, objectId: file.id,
  });
  const request = await c.requests.create(sender.actor, RequestInput.parse({ to: owner.actor.id, operations: [{
    name: 'file.update', input: { id: file.id, version: file.version, bytes: Buffer.from('updated').toString('base64url'), contentType: 'text/plain' },
  }] }));
  const project = await c.executions.start(owner.actor, [{ name: 'principal.create', input: { ownerId: owner.actor.id, name: 'File project' } }]);
  const snapshots = await c.db.all<{ id: string; snapshot: string }>('SELECT id,snapshot FROM executions');
  await c.db.transaction(async connection => {
    await connection.query('ALTER TABLE resources DROP CONSTRAINT resources_kind_check');
    await connection.query("UPDATE resources SET kind='object' WHERE kind='file'");
    await connection.query("ALTER TABLE resources ADD CONSTRAINT resources_kind_check CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring'))");
    await connection.query('ALTER TABLE file_blobs RENAME TO object_blobs');
    await connection.query('ALTER TABLE object_blobs RENAME CONSTRAINT file_blobs_pkey TO object_blobs_pkey');
    await connection.query('ALTER TABLE object_blobs RENAME CONSTRAINT file_blobs_resource_id_fkey TO object_blobs_resource_id_fkey');
    await connection.query("UPDATE audit_log SET action='object.upload' WHERE action='file.upload'");
    for (const saved of snapshots) {
      const snapshot = await c.vault.decrypt<{ operations: Array<{ name: string }>; results: Array<{ kind?: string; createKinds?: string[] } | null> }>(saved.snapshot, 'operation-execution:' + saved.id);
      for (const operation of snapshot.operations) operation.name = operation.name.replace(/^file\./, 'object.');
      for (const result of snapshot.results) {
        if (result?.kind === 'file') result.kind = 'object';
        if (result?.createKinds) result.createKinds = result.createKinds.map(kind => kind === 'file' ? 'object' : kind);
      }
      await connection.query('UPDATE executions SET snapshot=$2 WHERE id=$1', [saved.id,
        await c.vault.encrypt(snapshot, 'operation-execution:' + saved.id)]);
    }
    await connection.query("DELETE FROM schema_migrations WHERE name='003-files'");
  });
  await assert.rejects(migrateFiles(c.db, new Vault(randomBytes(32))));
  await createContext(f.config, { db: c.db, storage }, { migrate: true });
  await migrateFiles(c.db, c.vault);
  await c.db.assertReady();
  const retained = await c.resources.get(file.id);
  assert.equal(retained.kind, 'file'); assert.equal(retained.owner_id, file.ownerId);
  assert.equal(retained.private_data, row.private_data); assert.equal(retained.version, file.version);
  const headers = { authorization: 'Bearer ' + reader.token };
  const metadata = await app.inject({ url: '/api/resources/' + file.id, headers });
  assert.equal(metadata.statusCode, 200, metadata.body);
  assert.equal(FileResource.parse(metadata.json()).id, file.id);
  const content = await app.inject({ url: '/api/resources/' + file.id + '/content', headers });
  assert.equal(content.statusCode, 200, content.body); assert.deepEqual(content.rawPayload, original);
  const history = await c.executions.get(owner.actor, completed.id);
  assert.equal(history.operations[0]?.name, 'file.create');
  assert.equal(FileResource.parse(history.results[0]).id, file.id);
  const projectHistory = await c.executions.get(owner.actor, project.id);
  assert.ok(Principal.parse(projectHistory.results[0]).createKinds.includes('file'));
  const delivered = await c.requests.get(owner.actor, request.id);
  assert.equal(delivered.url, request.url); assert.equal(delivered.executionId, request.executionId);
  const waiting = await c.executions.get(owner.actor, request.executionId);
  assert.equal(waiting.operations[0]?.name, 'file.update');
  await c.requests.approve(owner.actor, request.id, []);
  const updated = await app.inject({ url: '/api/resources/' + file.id + '/content', headers });
  assert.equal(updated.body, 'updated');
  assert.equal((await c.billing.usage(owner.actor.id)).storageBytes, 7);
  assert.ok((await c.audit.list(owner.actor.id)).items.some(item => item.action === 'file.upload' && item.targetId === file.id));
  await c.files.remove(owner.actor, await c.resources.get(file.id));
  assert.equal(storage.files.size, 0);
});
