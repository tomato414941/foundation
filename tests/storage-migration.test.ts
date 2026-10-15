import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryObjects } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { Vault } from '../server/vault.js';
import { migrateFiles } from '../server/migrations/migrate-files.js';
import { migrateStorage } from '../server/migrations/migrate-storage.js';
import { ObjectResource, Principal, RequestInput } from '../shared/contracts.js';

for (const previous of ['file', 'object'] as const) {
  test(`${previous}形式の保存データと共有権限と依頼を移行し、同じIDでオブジェクトを読み更新する`, async t => {
    const f = await fixture({ FOUNDATION_BILLING_MODE: 'included' }), storage = new MemoryObjects();
    const c = await createContext(f.config, { db: f.db, storage }), app = await buildApp(c);
    t.after(async () => { await app.close(); await f.close(); });
    const owner = await f.person('Storage owner'), reader = await f.person('Reader'), sender = await f.person('Requester');
    const original = Buffer.from('{"kind":"file","name":"file.create","nested":{"kind":"object"}}');
    const completed = await c.executions.start(owner.actor, [{ name: 'object.create', input: {
      ownerId: owner.actor.id, name: 'note.txt', bytes: original.toString('base64url'), contentType: 'text/plain',
    } }]);
    const object = ObjectResource.parse(completed.results[0]), row = await c.resources.get(object.id);
    for (const relation of ['reader', 'user']) await c.relations.draw(owner.actor, {
      subjectId: reader.actor.id, relation, objectId: object.id,
    });
    const request = await c.requests.create(sender.actor, RequestInput.parse({ to: owner.actor.id, operations: [{
      name: 'object.update', input: { id: object.id, version: object.version, bytes: Buffer.from('updated').toString('base64url'), contentType: 'text/plain' },
    }] }));
    const project = await c.executions.start(owner.actor, [{ name: 'principal.create', input: { ownerId: owner.actor.id, name: 'Storage project' } }]);
    const snapshots = await c.db.all<{ id: string; snapshot: string }>('SELECT id,snapshot FROM executions');
    await c.db.transaction(async connection => {
      if (previous === 'file') {
        await connection.query('ALTER TABLE resources DROP CONSTRAINT resources_kind_check');
        await connection.query("UPDATE resources SET kind='file' WHERE kind='object'");
        await connection.query("ALTER TABLE resources ADD CONSTRAINT resources_kind_check CHECK (kind IN ('variable','connection','service','method','app','file','environment','function','keyring'))");
        await connection.query('ALTER TABLE object_blobs RENAME TO file_blobs');
        await connection.query('ALTER TABLE file_blobs RENAME CONSTRAINT object_blobs_pkey TO file_blobs_pkey');
        await connection.query('ALTER TABLE file_blobs RENAME CONSTRAINT object_blobs_resource_id_fkey TO file_blobs_resource_id_fkey');
        await connection.query("UPDATE audit_log SET action='file.upload' WHERE action='object.upload'");
        for (const saved of snapshots) {
          const snapshot = await c.vault.decrypt<{ operations: Array<{ name: string }>; results: Array<{ kind?: string; createKinds?: string[] } | null> }>(saved.snapshot, 'operation-execution:' + saved.id);
          for (const operation of snapshot.operations) operation.name = operation.name.replace(/^object\./, 'file.');
          for (const result of snapshot.results) {
            if (result?.kind === 'object') result.kind = 'file';
            if (result?.createKinds) result.createKinds = result.createKinds.map(kind => kind === 'object' ? 'file' : kind);
          }
          await connection.query('UPDATE executions SET snapshot=$2 WHERE id=$1', [saved.id,
            await c.vault.encrypt(snapshot, 'operation-execution:' + saved.id)]);
        }
      } else {
        await connection.query("DELETE FROM schema_migrations WHERE name='003-files'");
      }
      await connection.query("DELETE FROM schema_migrations WHERE name='004-storage'");
    });
    const migrate = previous === 'file' ? migrateStorage : migrateFiles;
    await assert.rejects(migrate(c.db, new Vault(randomBytes(32))));
    await createContext(f.config, { db: c.db, storage }, { migrate: true });
    await migrateStorage(c.db, c.vault);
    await c.db.assertReady();
    const retained = await c.resources.get(object.id);
    assert.equal(retained.kind, 'object'); assert.equal(retained.owner_id, object.ownerId);
    assert.equal(retained.private_data, row.private_data); assert.equal(retained.version, object.version);
    const headers = { authorization: 'Bearer ' + reader.token };
    const metadata = await app.inject({ url: '/api/resources/' + object.id, headers });
    assert.equal(metadata.statusCode, 200, metadata.body);
    assert.equal(ObjectResource.parse(metadata.json()).id, object.id);
    const content = await app.inject({ url: '/api/resources/' + object.id + '/content', headers });
    assert.equal(content.statusCode, 200, content.body); assert.deepEqual(content.rawPayload, original);
    const history = await c.executions.get(owner.actor, completed.id);
    assert.equal(history.operations[0]?.name, 'object.create');
    assert.equal(ObjectResource.parse(history.results[0]).id, object.id);
    const projectHistory = await c.executions.get(owner.actor, project.id);
    assert.ok(Principal.parse(projectHistory.results[0]).createKinds.includes('object'));
    const delivered = await c.requests.get(owner.actor, request.id);
    assert.equal(delivered.url, request.url); assert.equal(delivered.executionId, request.executionId);
    const waiting = await c.executions.get(owner.actor, request.executionId);
    assert.equal(waiting.operations[0]?.name, 'object.update');
    await c.requests.approve(owner.actor, request.id, []);
    const updated = await app.inject({ url: '/api/resources/' + object.id + '/content', headers });
    assert.equal(updated.body, 'updated');
    assert.equal((await c.billing.usage(owner.actor.id)).storageBytes, 7);
    assert.ok((await c.audit.list(owner.actor.id)).items.some(item => item.action === 'object.upload' && item.targetId === object.id));
    await c.objects.remove(owner.actor, await c.resources.get(object.id));
    assert.equal(storage.objects.size, 0);
  });
}
