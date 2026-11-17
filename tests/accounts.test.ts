import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';
import { AccessPolicy, ContentTypes, protect, reveal } from '../shared/custody.js';
import { encode, decode } from '../shared/encryption.js';
import { confirmedActor } from './confirmation-support.js';

test('他方のメールアドレスを確認してアカウントを統合し、保管した内容を引き継ぐ', async (t) => {
  const f = await fixture(),
    c = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    accounts = new Accounts(c);
  t.after(() => f.close());
  const target = await f.person('Keep'),
    source = await f.person('Merge');
  await c.authentication.beginEmail(
    'merge@example.com',
    'browser',
    '/account',
    'en',
    await confirmedActor(c.confirmations, source.actor, source.keys,
      { action: 'credential.addEmail', principalId: source.actor.id, email: 'merge@example.com' }),
    source.actor.id,
  );
  let params = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  await c.authentication.verifyEmail(params.get('challenge')!, params.get('token')!);
  const initial = await protect(encode('merge-value'), AccessPolicy.parse({ format: 2, id: crypto.randomUUID(),
    origin: f.config.origin, ownerId: source.actor.id, contentType: ContentTypes.value, revision: 1,
    authorities: [source.binding], readers: [source.binding], grants: [] }), 1, source.binding, source.keys);
  const variable = await c.custody.put(source.actor, { name: 'Saved value', content: initial });
  await c.authentication.beginEmail(
    'merge@example.com',
    'browser',
    '/account',
    'en',
    target.actor,
    undefined,
    target.actor.id,
  );
  params = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  const verified = await c.authentication.verifyEmail(params.get('challenge')!, params.get('token')!);
  assert.ok('mergeProof' in verified);
  if (!('mergeProof' in verified)) return;
  const plan = await accounts.plan(target.actor, verified.mergeProof);
  assert.equal(plan.from.id, source.actor.id);
  const moved = await protect(encode('merge-value'), { ...initial.policy, revision: 2, ownerId: target.actor.id,
    authorities: [target.binding], readers: [target.binding] }, 2, source.binding, source.keys, undefined, initial);
  const merging = { action: 'account.merge', principalId: target.actor.id, mergeId: verified.mergeProof };
  await assert.rejects(() => accounts.merge(target.actor, verified.mergeProof, {
    [variable.id]: { version: variable.version, content: moved } }), { code: 'confirmation_required' });
  await accounts.merge(await confirmedActor(c.confirmations, target.actor, target.keys, merging), verified.mergeProof,
    { [variable.id]: { version: variable.version, content: moved } });
  const row = await c.resources.get(variable.id);
  assert.equal(row.owner_id, target.actor.id);
  assert.equal(
    decode(await reveal((await c.custody.read(target.actor, row.id)).content, target.binding, target.keys.encryption)),
    'merge-value',
  );
  assert.equal((await c.authentication.authenticate(source.token))?.id, target.actor.id);
  await assert.rejects(() => accounts.merge(target.actor, verified.mergeProof, {}), {
    code: 'invalid_proof',
  });
});

