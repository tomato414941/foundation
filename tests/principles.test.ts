import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { flowFixture, jsonResponse } from './flow-support.js';
import { encode } from '../shared/encryption.js';
import { Resource } from '../shared/contracts.js';
import { ProtectedKinds } from '../shared/protected.js';
import type { ProtectedKindName } from '../shared/protected.js';
import { newSSHKey } from '../cli/src/ssh-access.js';
import { canonical } from '../shared/authority.js';
import { Task, signEnvironment } from '../shared/runtime-protocol.js';

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
  // An application's client secret.
  app: { kind: 'app', deposit: async (f: Flow, name: string) => item(f, saved(await f.operations.execute(
    { name: 'app.save', input: { ownerId: f.owner.actor.id, name, methodId: 'github:oauth', clientId: 'the-same-client' } },
    { clientSecret: 'the-same-secret', fields: {} }))) },
  // What a run returns when it keeps a value of the response it got as a variable of the name given.
  result: { kind: 'result', deposit: async (f: Flow, name: string) => {
    const started = await f.operations.execute({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
      environmentId: f.environment.manifest.id, operation: { kind: 'http', request: { url: 'https://service.example/value',
        method: 'GET' } }, save: { '/value': name } } });
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
