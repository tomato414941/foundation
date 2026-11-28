import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { CustodyClient } from '../shared/client.js';
import { ConnectionResource } from '../shared/contracts.js';
import { decode, encode } from '../shared/encryption.js';
import { KeySharingItem } from '../shared/protocol.js';

test('接続用アプリと認証情報を開ける相手に接続を共有する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const methodId = 'github:oauth';
  const app = await f.saveApp(methodId);
  const connection = await f.client.save({ id: crypto.randomUUID(), ownerId: f.owner.actor.id, kind: 'connection' },
    'GitHub', encode('fake-token'), { labels: { account: 'GitHub test account' }, metadata: {
      state: 'ready', methodId, methodKind: 'oauth', appId: app.id, generation: crypto.randomUUID(),
      accountId: 'account-1', accountVerified: true, scopes: [], scopesStatus: 'reported', outputs: ['GITHUB_TOKEN'],
    } });
  const base = '/api/connections/' + connection.id + '/shares/';
  const path = base + f.stranger.actor.id;
  const recipient = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.actor.id, f.stranger.keys);
  const keyless = await f.principals.create('No encryption key');
  await assert.rejects(f.client.api.json(base + keyless.id, { method: 'PUT', body: { permission: 'reveal' } }),
    { code: 'share_recipient_key_required' });
  await assert.rejects(f.client.api.json(path, { method: 'PUT', body: { permission: 'reveal' } }),
    { code: 'share_application_required' });
  await assert.rejects(recipient.read(connection.id), { code: 'forbidden' });

  await f.relations.draw(f.owner.actor, { objectId: app.id, subjectId: f.stranger.actor.id, relation: 'revealer' });
  await f.client.reprotect(app.id);
  const plan = await f.client.api.json(path + '/recipients?permission=reveal', {}, KeySharingItem);
  const { content, version } = await f.client.read(connection.id);
  await assert.rejects(f.client.api.json(path, { method: 'PUT', body: { permission: 'reveal',
    protection: { version, content: { ...content, revision: content.revision + 1 } } } }), { code: 'recipients_changed' });
  await assert.rejects(recipient.read(connection.id), { code: 'forbidden' });

  const protection = (await f.client.sharing([plan]))[connection.id];
  const update = { method: 'PUT', body: { permission: 'reveal', protection } };
  await f.client.api.json(path, update);
  await f.client.api.json(path, update);
  const shared = await recipient.read(connection.id);
  assert.equal(shared.content.revision, content.revision + 1);
  assert.equal(decode(await recipient.open(shared.content)), 'fake-token');

  const renewals = f.context.connectionOperations;
  const renewal = await renewals.prepare(f.owner.actor, crypto.randomUUID(), connection.id, shared.content.revision);
  await renewals.dispatch(f.owner.actor, renewal.id, renewal.fence);
  await renewals.uncertain(f.owner.actor, renewal.id, renewal.fence);
  const token = await recipient.seal(connection.id, encode('renewed-token'), shared.content.revision + 1, shared.content.metadata);
  const appRevision = (await recipient.read(app.id)).content.revision;
  await assert.rejects(recipient.api.json('/api/connections/' + connection.id + '/token',
    { method: 'PUT', body: { content: token, appRevision } }), { code: 'wrong_grant' });
  const edit = { method: 'PUT', body: { permission: 'update' } };
  await assert.rejects(f.client.api.json(path, edit), { code: 'connection_uncertain' });

  await renewals.refused(f.owner.actor, renewal.id, renewal.fence);
  await assert.rejects(f.client.api.json(path, edit), { code: 'reconnect_required' });
  const view = await recipient.api.json('/api/resources/' + connection.id, {}, ConnectionResource);
  assert.equal(view.data.state, 'reconnect');
  assert.ok(view.permissions.includes('reveal'));
  assert.ok(!view.permissions.includes('update'));
});
