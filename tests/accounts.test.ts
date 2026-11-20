import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';
import { openItem, sealItem } from '../shared/custody.js';
import { decode } from '../shared/encryption.js';

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
  const variable = await f.keep(source.actor, source.actor.id, 'Saved value', 'merge-value');
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
  assert.deepEqual(plan.recipients.map(recipient => recipient.id), [target.actor.id]);
  // The other account's key opens what it held, and the value is sealed for whoever uses what this account holds.
  const [item] = plan.protectedItems;
  const moved = await sealItem(await openItem(item!.content, source.keys.privateKey, source.keys.publicKey), plan.recipients,
    item!.content.revision + 1, item!.content.metadata);
  await accounts.merge(target.actor, verified.mergeProof, { [variable.id]: { version: variable.version, content: moved } });
  const row = await c.resources.get(variable.id);
  assert.equal(row.owner_id, target.actor.id);
  assert.equal(
    decode(await openItem((await c.custody.read(target.actor, row.id)).content, target.keys.privateKey, target.keys.publicKey)),
    'merge-value',
  );
  assert.equal((await c.authentication.authenticate(source.token))?.id, target.actor.id);
  await assert.rejects(() => accounts.merge(target.actor, verified.mergeProof, {}), {
    code: 'invalid_proof',
  });
});

