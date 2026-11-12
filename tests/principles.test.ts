import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { flowFixture } from './flow-support.js';
import { encode } from '../shared/encryption.js';
import { Resource } from '../shared/contracts.js';
import { ProtectedKinds } from '../shared/protected.js';
import type { ProtectedKindName } from '../shared/protected.js';
import { newSSHKey } from '../cli/src/ssh-access.js';

type Flow = Awaited<ReturnType<typeof flowFixture>>;

// Why: the user decided that a seal holds only what it cannot do without, and names things by id; an item's name is
// a label kept outside it. A name sealed in goes stale when the item is renamed (SSH keys once showed their old name
// in ssh-add -l), and is more than the seal needs.
// Intent: deposit the same thing twice under different names, each way Foundation makes sealed content, and open
// both. The whole contents are compared, so that no knowledge of their formats and no exceptions are needed.

// Each way Foundation makes sealed content, depositing the same thing under the name given and returning the item.
const ways = {
  // A value entered by its owner, kept as a variable.
  variable: { kind: 'variable', deposit: async (f: Flow, name: string) => saved(await f.operations.execute(
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name } }, { value: encode('the same value') })) },
  // A private key made by the CLI and kept as a variable, as foundation ssh-key create --store does.
  sshKey: { kind: 'variable', deposit: async (f: Flow, name: string) => saved(await f.operations.execute(
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name } }, { value: encode(newSSHKey().privateKey) })) },
  // An API key entered for a connection.
  connection: { kind: 'connection', deposit: async (f: Flow, name: string) =>
    (await f.saveConnection({ methodId: 'cloudrift:api_key', name, fields: { token: 'the-same-token' } })).id },
  // An application's client secret.
  app: { kind: 'app', deposit: async (f: Flow, name: string) => saved(await f.operations.execute(
    { name: 'app.save', input: { ownerId: f.owner.actor.id, name, methodId: 'github:oauth', clientId: 'the-same-client' } },
    { clientSecret: 'the-same-secret', fields: {} })) },
} satisfies Record<string, { kind: ProtectedKindName; deposit: (f: Flow, name: string) => Promise<string> }>;
type Way = keyof typeof ways;
// A way of making each kind of item that keeps sealed content: a new kind does not compile until one is given above.
const madeBy: Record<ProtectedKindName, Way> = { variable: 'variable', connection: 'connection', app: 'app' };

function saved(result: unknown) {
  const resource = (result as { kind?: string; resource?: { id: string } }).resource;
  if ((result as { kind?: string }).kind !== 'saved' || !resource) throw new Error('Expected a saved item.');
  return resource.id;
}
// Deposits in a database of its own, with the randomness the client draws fixed, so that two deposits differ only in
// the name. Ids drawn this way repeat between the two deposits, which is why they never share a database.
async function depositAlone(deposit: (f: Flow, name: string) => Promise<string>, name: string) {
  const f = await flowFixture();
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
    const id = await deposit(f, name);
    const item = await f.client.api.json('/api/resources/' + id, {}, Resource);
    return { kind: item.kind, content: Buffer.from(await f.client.reveal(id)) };
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
