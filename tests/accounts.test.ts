import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { Accounts } from '../server/accounts.js';
import { AccessPolicy, ContentTypes, protect, reveal } from '../shared/custody.js';
import { encode, decode } from '../shared/encryption.js';
import { flowFixture } from './flow-support.js';
import { FunctionClient } from '../shared/function-client.js';
import { CustodyClient } from '../shared/client.js';
import { JournalTrust } from '../runtime/trust.js';
import { MemoryJournal } from './delegation-support.js';
import { FunctionDefinition, Resource, RequestInput } from '../shared/contracts.js';
import { FunctionPublication, FunctionSettingsApproval } from '../shared/function-api.js';
import { Execution } from '../shared/executions.js';
import { z } from 'zod';

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
  await accounts.merge(target.actor, verified.mergeProof, { [variable.id]: { version: variable.version, content: moved } });
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

test('アカウント統合で関数と完了した実行履歴を引き継ぎ、元の実行者を記録する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const source = f.stranger, target = f.owner, c = f.context, accounts = new Accounts(c);
  for (const relation of ['reader', 'runner']) await c.relations.draw(target.actor, {
    subjectId: source.actor.id, relation, objectId: f.environment.manifest.id });
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding); await trust.rememberBinding(source.binding);
  const functions = new FunctionClient(f.api(source.token), new CustodyClient(f.api(source.token), f.config.origin, source.binding, source.keys, trust));
  const definition = FunctionDefinition.parse({ program: { kind: 'command', command: ['node', '-e', 'console.log("result")'] }, result: 'text' });
  const fn = await functions.save({ ownerId: source.actor.id, name: 'Merged function', definition });
  await functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const invocation = await functions.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.equal((await functions.result(invocation.id)).state, 'succeeded');
  const operation = { name: 'principal.create', input: { ownerId: '$approver', name: 'Requested principal' } };
  const outgoing = await c.requests.create(source.actor, RequestInput.parse({ to: f.executorIdentity.actor.id, operations: [operation] }));
  const incoming = await c.requests.create(f.executorIdentity.actor, RequestInput.parse({ to: source.actor.id, operations: [operation] }));
  await c.authentication.beginEmail('history@example.com', 'browser', '/account', 'en', source.actor, source.actor.id);
  let params = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  await c.authentication.verifyEmail(params.get('challenge')!, params.get('token')!);
  await c.authentication.beginEmail('history@example.com', 'browser', '/account', 'en', target.actor, undefined, target.actor.id);
  params = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  const verified = await c.authentication.verifyEmail(params.get('challenge')!, params.get('token')!);
  assert.ok('mergeProof' in verified); if (!('mergeProof' in verified)) return;
  await accounts.merge(target.actor, verified.mergeProof, {});
  const history = await f.functions.result(invocation.id);
  assert.equal(history.state, 'succeeded'); assert.equal(history.ownerId, target.actor.id);
  assert.equal(history.creator.id, source.actor.id); assert.equal(history.results[0], 'result\n');
  assert.ok((await c.executions.list(target.actor)).items.some(item => item.id === invocation.id));
  const deliveries = (await c.requests.list(target.actor)).items;
  assert.equal(deliveries.find(item => item.id === outgoing.id)!.from.id, source.actor.id);
  assert.equal(deliveries.find(item => item.id === incoming.id)!.to!.id, target.actor.id);
  assert.equal(deliveries.find(item => item.id === incoming.id)!.state, 'cancelled');
  assert.equal((await f.functions.settings(fn.id)).state, 'publication_required');
  await assert.rejects(c.authorization.active({ id: source.actor.id }), { code: 'unauthenticated' });
  const received = await f.functions.get(fn.id);
  await f.functions.save({ ownerId: received.ownerId, resourceId: fn.id, version: received.version, name: received.name, definition });
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const next = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  assert.equal((await f.functions.result(next.id)).state, 'succeeded');
  const exported: Array<Record<string, unknown>> = [];
  for await (const line of accounts.export(target.actor, target.actor.id)) exported.push(JSON.parse(line));
  assert.equal(z.array(z.object({ id: z.uuid() })).parse(exported[0]!.mergedIdentities)[0]!.id, source.actor.id);
  const saved = exported.find(entry => entry.type === 'resource' && Resource.safeParse(entry.resource).data?.id === fn.id)!;
  assert.equal(FunctionPublication.parse(saved.publication).ownerId, target.actor.id);
  assert.ok(z.object({ approval: FunctionSettingsApproval }).parse(saved.executionSettings).approval.signature);
  const recorded = exported.find(entry => entry.type === 'execution' && Execution.safeParse(entry.execution).data?.id === invocation.id)!;
  assert.equal(Execution.parse(recorded.execution).creator.id, source.actor.id);
});
