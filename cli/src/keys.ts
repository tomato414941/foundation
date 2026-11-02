import { mkdir, readdir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Client } from './client.js';
import { configPath, saveIdentity } from './config.js';
import type { IdentityConfig } from './config.js';
import { FileJournal } from '../../runtime/journal.js';
import { journalLock } from '../../runtime/lock.js';
import { KeysReplaced, followKeys, rotateKeys } from '../../shared/key-rotations.js';
import type { BoundKeys, IdentityKeys } from '../../shared/authority.js';

const custody = (binding: BoundKeys) => join(dirname(configPath()), 'custody', binding.id);
const exists = (path: string) => stat(path).then(() => true, () => false);

// Moves what this machine recorded with its previous keys to the directory of the new ones: each journal entry is
// opened with the previous keys and written again with the new ones, and an executor's workspace moves with it.
// An executor that is running keeps its directory and the previous keys stay saved, so that the executor moves it
// once it stops for the new keys. Returns whether everything moved.
async function moveCustody(origin: string, previous: { binding: BoundKeys; keys: IdentityKeys },
  next: { binding: BoundKeys; keys: IdentityKeys }) {
  const from = custody(previous.binding), to = custody(next.binding);
  if (!await exists(from)) return true;
  const move = async (relative: string) => {
    const source = new FileJournal(join(from, relative), origin, previous.binding, previous.keys);
    const target = new FileJournal(join(to, relative), origin, next.binding, next.keys);
    for (const id of await source.keys('')) {
      const value = await source.read(id);
      if (value !== null) await target.write(id, value);
    }
  };
  let kept = false;
  for (const relative of ['client', 'connections']) await move(relative);
  const executors = await readdir(join(from, 'executors')).catch(() => [] as string[]);
  for (const id of executors) {
    let release;
    try { release = await journalLock(join(from, 'executors', id, 'process.lock')); }
    catch { kept = true; continue; }
    try {
      await move(join('executors', id));
      await mkdir(join(to, 'executors', id), { recursive: true, mode: 0o700 });
      if (await exists(join(from, 'executors', id, 'workspace')))
        await rename(join(from, 'executors', id, 'workspace'), join(to, 'executors', id, 'workspace'));
    } finally { await release(); }
    await rm(join(from, 'executors', id), { recursive: true, force: true });
  }
  if (!kept) await rm(from, { recursive: true, force: true });
  return !kept;
}

// The machine's identity with the keys it holds now: when the principal rotated its keys elsewhere, it follows the
// handoffs from the keys it held, moves its records to the new keys, and saves them in place of the previous ones.
export async function currentIdentity(identity: IdentityConfig): Promise<IdentityConfig> {
  if (!identity.keys || !identity.binding) return identity;
  let next;
  try { next = await followKeys(new Client(identity), { binding: identity.binding, keys: identity.keys }); }
  catch (error) {
    if (!(error instanceof KeysReplaced)) throw error;
    process.stderr.write('foundation: ' + error.message + '\n');
    return identity;
  }
  if (!next) return identity;
  const updated = { ...identity, keys: next.keys, binding: next.binding };
  const moved = await moveCustody(identity.origin, { binding: identity.binding, keys: identity.keys }, next);
  if (process.env.FOUNDATION_TOKEN)
    process.stderr.write('foundation: This identity uses new keys. Replace FOUNDATION_PRIVATE_KEYS and FOUNDATION_KEY_BINDING with them.\n');
  else if (moved) await saveIdentity(updated);
  return updated;
}

// Replaces this machine's identity keys, and keeps the new ones once every item is ready for them.
export async function rotateIdentity(identity: IdentityConfig) {
  if (!identity.keys || !identity.binding) throw new Error('Use a sign-in key with encryption and signing keys for this operation.');
  if (process.env.FOUNDATION_TOKEN) throw new Error('Rotate the keys from a machine that saves its identity.');
  const held = { binding: identity.binding, keys: identity.keys };
  const result = await rotateKeys(new Client(identity), held);
  if (result.state === 'waiting') return result;
  // Until a running executor has moved its records, the previous keys stay saved and lead to the new ones.
  if (await moveCustody(identity.origin, held, result)) await saveIdentity({ ...identity, keys: result.keys, binding: result.binding });
  return { state: result.state, bindingId: result.binding.id, generation: result.binding.generation };
}
