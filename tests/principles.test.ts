import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { flowFixture, jsonResponse } from './flow-support.js';
import { decode, encode } from '../shared/encryption.js';
import { FunctionDefinition, Resource } from '../shared/contracts.js';
import { ProtectedKinds } from '../shared/protected.js';
import type { ProtectedKindName } from '../shared/protected.js';
import { newSSHKey } from '../cli/src/ssh-access.js';
import { canonical, hash } from '../shared/authority.js';
import { ContentTypes, protect } from '../shared/custody.js';
import { Task, signEnvironment } from '../shared/runtime-protocol.js';
import { ExecutionClient } from '../shared/execution-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';

type Flow = Awaited<ReturnType<typeof flowFixture>>;

// Why: the user decided that a seal holds only what it cannot do without, and names things by id; an item's name is
// a label kept outside it. A name sealed in goes stale when the item is renamed (SSH keys once showed their old name
// in ssh-add -l), and is more than the seal needs.
// Intent: deposit the same thing twice under different names, each way Foundation makes sealed content, and open
// both. The whole contents are compared, so that no knowledge of their formats and no exceptions are needed.

// Each way Foundation makes sealed content, depositing the same thing under the name given and returning what its
// readers open.
const ways = {
  // A value entered by its owner, kept as a variable.
  variable: { kind: 'variable', deposit: async (f: Flow, name: string) => item(f, saved(await f.operations.execute(
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name } }, { value: encode('the same value') }))) },
  // A private key made by the CLI and kept as a variable, as foundation ssh-key create --store does.
  sshKey: { kind: 'variable', deposit: async (f: Flow, name: string) => item(f, saved(await f.operations.execute(
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name } }, { value: encode(newSSHKey().privateKey) }))) },
  // An API key entered for a connection.
  connection: { kind: 'connection', deposit: async (f: Flow, name: string) =>
    item(f, (await f.saveConnection({ methodId: 'cloudrift:api_key', name, fields: { token: 'the-same-token' } })).id) },
  // An API key entered for a connection through a connection method of the name given.
  method: { kind: 'connection', deposit: async (f: Flow, name: string) => {
    const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources', { method: 'POST',
      body: { kind: 'method', name, definition: await f.method('cloudrift:api_key') } }, Resource);
    return item(f, (await f.saveConnection({ methodId: method.id, fields: { token: 'the-same-token' } })).id);
  } },
  // An OAuth token of a connection sealed in the earlier format, with its method of the name given and its account's
  // display name, as its owner's device seals it again.
  earlier: { kind: 'connection', deposit: async (f: Flow, name: string) => {
    const policy = await f.client.policy(f.owner.actor.id, ContentTypes.tokenSet), generation = crypto.randomUUID();
    const material = { format: 2, methodId: 'openrouter:oauth', method: { ...await f.method('openrouter:oauth'), name },
      generation, appId: null, appGeneration: null, oauth: { accessToken: 'the-same-token', expiresAt: null, scopes: [],
        scopesStatus: 'unknown', account: '', accountName: name, accountVerified: false, extra: {}, facts: {} } };
    // What the earlier format signed beside it, which named the method by id alone.
    const metadata = { methodId: 'openrouter:oauth', methodKind: 'oauth', generation, authorizationDigest: await hash({ generation }),
      appId: null, accountId: null, accountVerified: false, scopes: [], scopesStatus: 'unknown', outputs: ['OPENROUTER_API_KEY'],
      state: 'ready' };
    const content = await protect(encode(canonical(material)), policy, 1, f.owner.binding, f.owner.keys, metadata);
    await f.resources.insert(f.owner.actor.id, 'connection', 'Earlier connection', { ...metadata, methodName: name, account: '' },
      { id: policy.id });
    await f.db.pool.query('INSERT INTO resource_custody(resource_id,content) VALUES($1,$2)', [policy.id, JSON.stringify(content)]);
    await f.client.reprotectPending();
    return item(f, policy.id);
  } },
  // An application's client secret.
  app: { kind: 'app', deposit: async (f: Flow, name: string) => item(f, saved(await f.operations.execute(
    { name: 'app.save', input: { ownerId: f.owner.actor.id, name, methodId: 'github:oauth', clientId: 'the-same-client' } },
    { clientSecret: 'the-same-secret', fields: {} }))) },
  // What a run returns when it keeps a value of the response it got as a variable of the name given.
  result: { kind: 'result', deposit: async (f: Flow, name: string) => {
    const started = await f.operations.execute({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
      environmentId: f.environment.manifest.id, operation: { kind: 'http', request: { url: 'https://service.example/value',
        method: 'GET' } }, names: { '/value': name } } });
    if (!('kind' in started) || started.kind !== 'run') throw new Error('Expected a run.');
    await f.executor.tick();
    const task = await f.client.api.json('/api/runtime/runs/' + started.task.id, {}, Task);
    return { kind: 'result', content: encode(canonical(await f.client.result(task))) };
  } },
} satisfies Record<string, { kind: ProtectedKindName | 'result'; deposit: (f: Flow, name: string) => Promise<Opened> }>;
type Way = keyof typeof ways;
type Opened = { kind: string; content: Uint8Array };
// A way of making each kind of item that keeps sealed content: a new kind does not compile until one is given above.
const madeBy: Record<ProtectedKindName, Way> = { variable: 'variable', connection: 'connection', app: 'app' };

function saved(result: unknown) {
  const resource = (result as { kind?: string; resource?: { id: string } }).resource;
  if ((result as { kind?: string }).kind !== 'saved' || !resource) throw new Error('Expected a saved item.');
  return resource.id;
}
// An item as its reader opens it: its kind, and the content sealed for it.
async function item(f: Flow, id: string): Promise<Opened> {
  const resource = await f.client.api.json('/api/resources/' + id, {}, Resource);
  return { kind: resource.kind, content: await f.client.reveal(id) };
}
// Deposits in a database of its own, with the randomness the client draws fixed, so that two deposits differ only in
// the name. Ids drawn this way repeat between the two deposits, which is why they never share a database. Every request
// sent out gets the same response, carrying a value a run can keep.
async function depositAlone(deposit: (f: Flow, name: string) => Promise<Opened>, name: string) {
  const f = await flowFixture(() => jsonResponse({ value: 'the same value' }));
  const random = globalThis.crypto, counter = { value: 0 };
  const bytes = (length: number) => {
    const out = Buffer.alloc(length);
    for (let at = 0; at < length; at += 32) createHash('sha256').update('fixed ' + counter.value++).digest().copy(out, at);
    return out;
  };
  const getRandomValues = <T extends ArrayBufferView | null>(array: T) => {
    if (array) new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(bytes(array.byteLength));
    return array;
  };
  const randomUUID = () => {
    const value = bytes(16);
    value[6] = (value[6]! & 0x0f) | 0x40; value[8] = (value[8]! & 0x3f) | 0x80;
    const hex = value.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as `${string}-${string}-${string}-${string}-${string}`;
  };
  try {
    Object.assign(random, { getRandomValues, randomUUID });
    const opened = await deposit(f, name);
    return { kind: opened.kind, content: Buffer.from(opened.content) };
  } finally {
    delete (random as Partial<Crypto>).getRandomValues; delete (random as Partial<Crypto>).randomUUID;
    await f.close();
  }
}

for (const way of Object.keys(ways) as Way[]) {
  test(`同じものを違う名前で預けると、封じる中身は同じになる（${way}）`, async () => {
    const first = await depositAlone(ways[way].deposit, 'Alpha');
    const second = await depositAlone(ways[way].deposit, 'ベータ, the second name');
    assert.equal(first.kind, ways[way].kind);
    assert.deepEqual(second.content, first.content);
  });
}

test('封をする種類のそれぞれを、その種類を作る預け方で確かめる', () => {
  assert.deepEqual(Object.keys(madeBy).sort(), [...ProtectedKinds].sort());
  for (const kind of ProtectedKinds) assert.equal(ways[madeBy[kind]].kind, kind);
});

// Why: the user decided that signatures, like seals, name things only by what identifies them; an item's name is a
// label kept in one place, Foundation. An executor once signed the name of its environment into its registration, so
// each registration it signed again, as after an update, put that name back over the one given in Foundation.
// Intent: rename an environment in Foundation, have its executor sign its registration again as it does after an
// update, and read the name back.
test('作業用の機械が登録し直しても、Foundation で付けた名前のまま変わらない', async () => {
  const f = await flowFixture();
  try {
    const { manifest } = f.environment;
    const current = await f.client.api.json('/api/resources/' + manifest.id, {}, Resource);
    await f.client.api.json('/api/resources/' + manifest.id, { method: 'PATCH',
      body: { version: current.version, name: 'Renamed in Foundation' } }, Resource);
    await f.context.delegation.register(f.executorIdentity.actor,
      await signEnvironment({ ...manifest, revision: manifest.revision + 1 }, f.executorIdentity.keys));
    assert.equal((await f.client.api.json('/api/resources/' + manifest.id, {}, Resource)).name, 'Renamed in Foundation');
  } finally { await f.close(); }
});

// Why: the user decided that what an owner signs to allow something names it by what it does; a description or a label
// is kept in one place, Foundation. A function's owner once signed its description and the labels of its parameters with
// its program, so describing it again took back the approvals given to run it and to read its inputs.
// Intent: approve a function that reads an input, describe it and its parameter again, and run it as approved.
test('関数の説明と引数の見出しを変えても、出した許可のまま実行できる', async () => {
  const f = await flowFixture();
  try {
    const definition = FunctionDefinition.parse({ description: 'Repeat a message.', program: { kind: 'command',
      command: ['node', '-e', 'let text="";process.stdin.on("data",c=>text+=c);process.stdin.on("end",()=>' +
        'console.log(JSON.stringify({message:JSON.parse(text).message,read:!!process.env.INPUT})));'],
      inputs: [{ name: 'INPUT', source: { id: f.resource.id } }], timeoutSeconds: 5 },
      parameters: [{ name: 'message', label: 'Message' }] });
    const fn = await f.functions.save({ ownerId: f.owner.actor.id, name: 'Repeater', definition });
    await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
    await f.functions.save({ ownerId: f.owner.actor.id, name: 'Repeater', resourceId: fn.id, version: fn.version,
      definition: { ...definition, description: 'Repeat a message, described again.',
        parameters: [{ ...definition.parameters[0]!, label: 'Words to repeat' }] } });
    const invoked = await f.functions.invoke(fn.id, { message: 'Still approved' });
    await f.functionExecutor.tick();
    assert.deepEqual((await f.functions.result(invoked.id)).results[0], { message: 'Still approved', read: true });
  } finally { await f.close(); }
});

// Why: the user decided that what is signed names things by what identifies them. A reviewed run once named the
// variables it keeps values in by their names, so a value went to whichever variable had that name when the run went
// ahead: a variable renamed in between was passed over, and another that had taken its name was written over.
// Intent: ask for a run that keeps a value in a variable, rename it and give its name to another before the run goes
// ahead, and read both.
test('保存先の変数は、名前を変えて別の変数がその名前になっても、指した変数に保存される', async () => {
  const f = await flowFixture(() => jsonResponse({ value: 'the kept value' }));
  try {
    const variable = async () => saved(await f.operations.execute(
      { name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Token' } }, { value: encode('before') }));
    const target = await variable();
    const started = await f.operations.start({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
      environmentId: f.environment.manifest.id, operation: { kind: 'http', request: { url: 'https://service.example/value',
        method: 'GET' } }, save: { '/value': target } } });
    const current = await f.client.api.json('/api/resources/' + target, {}, Resource);
    await f.client.api.json('/api/resources/' + target, { method: 'PATCH',
      body: { version: current.version, name: 'Renamed token' } }, Resource);
    const other = await variable();
    await f.operations.continue(started.id);
    await f.executor.tick();
    assert.equal(decode(await f.client.reveal(target)), 'the kept value');
    assert.equal(decode(await f.client.reveal(other)), 'before');
  } finally { await f.close(); }
});

// Why: the user decided that a seal holds only what it cannot do without. A connection being made once had its progress
// sealed with the connection's name and with the method it was made through, that method's name and description
// included, though Foundation keeps them as labels.
// Intent: start connecting through a method under a name and a description given here, open the progress sealed for the
// device that started it, and look for them in it.
test('つなぎかけの接続の進み具合は、接続とつなぎ方の名前や説明を入れずに封をする', async () => {
  const f = await flowFixture();
  try {
    const name = 'ベータ, the second name', description = 'A description given here.';
    const definition = await f.method('openrouter:oauth');
    if (definition.kind !== 'oauth') throw new Error('Expected an OAuth method.');
    const method = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources', { method: 'POST',
      body: { kind: 'method', name, definition: { ...definition, config: { ...definition.config, hint: description } } } }, Resource);
    const store = new RemoteFlowStore(f.client);
    const operations = new ExecutionClient(f.client, new ConnectionClient(f.client, store, f.transport, 'cli'));
    const progress = await operations.execute({ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: method.id, name } });
    if (!('flow' in progress)) throw new Error('Expected a connection being made.');
    const sealed = JSON.stringify(await store.records.get(progress.flow.id, z.unknown()));
    assert.equal(sealed.includes(name) || sealed.includes(description), false);
  } finally { await f.close(); }
});
