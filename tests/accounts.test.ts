import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';
import { open, decode } from '../shared/encryption.js';

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
    source.actor,
    source.actor.id,
  );
  let params = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  await c.authentication.verifyEmail(params.get('challenge')!, params.get('token')!);
  const secret = await c.inputs.keep(
    source.actor,
    source.actor.id,
    'Saved value',
    Buffer.from('merge-secret'),
  );
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
  await accounts.merge(target.actor, verified.mergeProof, {});
  const row = await c.resources.get(secret.id);
  assert.equal(row.owner_id, target.actor.id);
  assert.equal(
    decode(await open(row.sealed!, target.keys.privateKey, target.actor.id, 'resource:' + row.id)),
    'merge-secret',
  );
  assert.equal((await c.authentication.authenticate(source.token))?.id, target.actor.id);
  await assert.rejects(() => accounts.merge(target.actor, verified.mergeProof, {}), {
    code: 'invalid_proof',
  });
});
