import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanupIdentities } from '../deploy/release/cleanup.mjs';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient } from '../shared/client.js';
import { FunctionClient } from '../shared/function-client.js';
import { Operations } from '../shared/custody.js';
import { FUNCTION_RUNTIME_VERSION, signEnvironment } from '../shared/runtime-protocol.js';
import { JournalTrust } from '../runtime/trust.js';

test('本番確認用の関数履歴とプリンシパルを片付け、利用者の関数履歴を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const definition = () => ({ program: { kind: 'http' as const,
    request: { method: 'GET' as const, url: 'https://api.example.com/check' } }, parameters: [], result: 'json' as const });
  const existing = await f.functions.save({ ownerId: f.owner.actor.id, name: 'User function', definition: definition() });
  await f.functions.configure(existing.id, { environmentId: f.environment.manifest.id });
  const history = await f.functions.invoke(existing.id);
  const owner = await f.personWithKeys('Disposable verification owner'), executor = await f.personWithKeys('Disposable verification executor');
  await f.relations.draw(owner.actor, { subjectId: executor.actor.id, relation: 'agent', objectId: owner.actor.id });
  const environment = await signEnvironment({ format: 3, id: crypto.randomUUID(), origin: f.config.origin,
    ownerId: owner.actor.id, name: 'Disposable environment', executor: executor.binding, operatorId: executor.actor.id,
    driver: 'attached', capabilities: Object.values(Operations), functionVersion: FUNCTION_RUNTIME_VERSION, isolation: 'process', revision: 1 }, executor.keys);
  await f.context.delegation.register(executor.actor, environment);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(executor.binding);
  const api = f.api(owner.token), custody = new CustodyClient(api, f.config.origin, owner.binding, owner.keys, trust);
  const functions = new FunctionClient(api, custody);
  const temporary = await functions.save({ ownerId: owner.actor.id, name: 'Verification function', definition: definition() });
  await functions.configure(temporary.id, { environmentId: environment.manifest.id });
  const verification = await functions.invoke(temporary.id);
  assert.equal((await functions.result(verification.id)).state, 'running');
  await functions.cancel(verification.id);
  await functions.remove(temporary.id);
  await f.context.resources.delete(owner.actor, await f.context.resources.get(environment.manifest.id));
  await cleanupIdentities(f.context.db, [owner.actor.id, executor.actor.id]);
  await assert.rejects(f.context.principals.get(owner.actor.id), { code: 'not_found' });
  await assert.rejects(f.context.principals.get(executor.actor.id), { code: 'not_found' });
  assert.equal((await f.functions.result(history.id)).state, 'running');
  assert.equal((await f.functions.get(existing.id)).name, 'User function');
});
