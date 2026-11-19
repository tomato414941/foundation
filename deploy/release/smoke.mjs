import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { configuration } from '../../dist/server/config.js';
import { createContext } from '../../dist/server/context.js';
import { Client } from '../../dist/cli/src/client.js';
import { saveIdentity } from '../../dist/cli/src/config.js';
import { newIdentityKeys, bindKeys, signBinding } from '../../dist/shared/authority.js';
import { CustodyClient } from '../../dist/shared/client.js';
import { FileJournal } from '../../dist/runtime/journal.js';
import { JournalTrust } from '../../dist/runtime/trust.js';
import { ContentTypes } from '../../dist/shared/custody.js';
import { encode, decode } from '../../dist/shared/encryption.js';
import { followKeys, rotateKeys } from '../../dist/shared/key-rotations.js';
import { confirmationHeader, signConfirmation } from '../../dist/shared/confirmations.js';
import { cleanupIdentities } from './cleanup.mjs';

// Only disposable identities and test material are used, including against production.
const config = await configuration();
const context = await createContext(config);
const directory = await mkdtemp(join(tmpdir(), 'foundation-release-smoke-'));
const identities = [], resources = [];
let finished = false, storageVerified = false;
const check = async path => {
  const response = await fetch(config.origin + path, { signal: AbortSignal.timeout(30_000), redirect: 'error' });
  assert.equal(response.status, 200, 'Public request failed: ' + path);
  return response;
};
try {
  assert.equal((await (await check('/health')).json()).ok, true);
  const html = await (await check('/signin')).text();
  assert.ok(html.includes('/assets/'), 'The sign-in page must load its built assets.');
  const asset = html.match(/(?:src|href)="(\/assets\/[^"<>]+\.(?:js|css))"/);
  assert.ok(asset); await check(asset[1]);
  for (let index = 0; index < 2; index++) {
    const keys = await newIdentityKeys();
    const binding = bindKeys(crypto.randomUUID(), keys);
    const enrollment = await context.authentication.enroll('Release verification ' + crypto.randomUUID(), await signBinding(binding, keys));
    identities.push(enrollment.principal.id);
    const client = new Client({ origin: config.origin, principalId: enrollment.principal.id, token: enrollment.token, keys, binding });
    const trust = new JournalTrust(new FileJournal(join(directory, String(index)), config.origin, binding, keys));
    const custody = new CustodyClient(client, config.origin, binding, keys, trust);
    identities[index] = { id: binding.principalId, client, custody, binding, trust };
  }
  const [owner, caller] = identities;
  {
    // A disposable identity replaces its keys; another sign-in key that held the previous keys follows to the new ones,
    // and both read the same value afterwards.
    const keys = await newIdentityKeys();
    const binding = bindKeys(crypto.randomUUID(), keys);
    const enrollment = await context.authentication.enroll('Release key rotation ' + crypto.randomUUID(), await signBinding(binding, keys));
    identities.push(enrollment.principal.id);
    const client = new Client({ origin: config.origin, principalId: binding.principalId, token: enrollment.token, keys, binding });
    const open = (api, held, name) => new CustodyClient(api, config.origin, held.binding, held.keys,
      new JournalTrust(new FileJournal(join(directory, name), config.origin, held.binding, held.keys)));
    const value = crypto.randomUUID(), before = open(client, { binding, keys }, 'rotation-before');
    const saved = await before.save('Release rotation value', encode(value), await before.policy(binding.principalId, ContentTypes.value));
    const second = await context.authentication.issueKey(binding.principalId, 'Release second device');
    const other = new Client({ origin: config.origin, principalId: binding.principalId, token: second.token, keys, binding });
    const rotated = await rotateKeys(client, { binding, keys });
    assert.equal(rotated.state, 'committed');
    assert.equal((await client.json('/api/identities/' + binding.principalId + '/binding')).binding.id, rotated.binding.id);
    assert.equal(decode(await open(client, rotated, 'rotation-after').reveal(saved.id)), value);
    const followed = await followKeys(other, { binding, keys });
    assert.equal(followed.binding.id, rotated.binding.id);
    assert.equal(decode(await open(other, followed, 'rotation-followed').reveal(saved.id)), value);
  }
  {
    // A disposable identity cannot issue a sign-in key with its token alone. Signing the change through the
    // confirmation API lets the same request through once, and the confirmation is not accepted again.
    const keys = await newIdentityKeys(), binding = bindKeys(crypto.randomUUID(), keys);
    const enrollment = await context.authentication.enroll('Release confirmation ' + crypto.randomUUID(), await signBinding(binding, keys));
    identities.push(enrollment.principal.id);
    const client = new Client({ origin: config.origin, principalId: binding.principalId, token: enrollment.token, keys, binding });
    const issue = confirmation => fetch(new URL('/api/principals/' + binding.principalId + '/credentials', config.origin), {
      method: 'POST', redirect: 'error', body: JSON.stringify({ name: 'Release confirmed key' }),
      headers: { authorization: 'Bearer ' + enrollment.token, 'content-type': 'application/json',
        ...(confirmation ? { [confirmationHeader]: confirmation } : {}) },
    });
    const refused = await issue();
    const needed = (await refused.json()).error;
    assert.equal(refused.status, 403); assert.equal(needed.code, 'confirmation_required');
    const view = await client.json('/api/confirmations', { method: 'POST', body: { operation: needed.details.operation } });
    await client.json('/api/confirmations/' + view.id + '/proof', { method: 'POST',
      body: { method: 'signature', signature: await signConfirmation(view, keys.signing) } });
    assert.equal((await issue(view.id)).status, 201);
    const reused = await issue(view.id);
    assert.equal(reused.status, 403); assert.equal((await reused.json()).error.code, 'confirmation_invalid');
  }
  // The CLI of this release opens a value on this machine and hands it to a local command, which sees it masked
  // nowhere but in its own environment.
  const secret = 'release-input-' + crypto.randomUUID();
  const input = await owner.custody.save('Release input', encode(secret), await owner.custody.policy(owner.id, ContentTypes.value));
  resources.push(input.id);
  const home = join(directory, 'cli');
  process.env.XDG_CONFIG_HOME = home;
  await saveIdentity(owner.client.identity);
  const command = spawn(process.execPath, ['/app/release/cli.mjs', 'exec', '--inputs', JSON.stringify([{ name: 'TOKEN', source: { id: input.id } }]),
    '--', process.execPath, '-e', 'process.stdout.write(process.env.TOKEN === process.argv[1] ? "opened" : "unopened")', secret],
    { env: { ...process.env, XDG_CONFIG_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
  let printed = '';
  command.stdout.on('data', chunk => { printed += chunk; });
  assert.equal(await new Promise(resolve => command.once('close', resolve)), 0);
  assert.equal(printed, 'opened');
  await assert.rejects(caller.custody.read(input.id));
  if (context.objects.store.enabled) {
    const content = 'Foundation release storage verification';
    const file = await caller.client.json('/api/principals/' + caller.id + '/objects?name=release-check.txt&contentType=text/plain',
      { method: 'POST', raw: encode(content) });
    resources.push(file.id);
    assert.equal(file.kind, 'object');
    const listed = await caller.client.json('/api/principals/' + caller.id + '/resources?kind=object');
    assert.ok(listed.items.some(item => item.id === file.id && item.kind === 'object'));
    const linked = await caller.client.json('/api/operations', { method: 'POST', body: { name: 'object.link', input: { id: file.id } } });
    assert.equal(linked.state, 'succeeded');
    const downloaded = await fetch(linked.result.url, { signal: AbortSignal.timeout(30_000), redirect: 'error' });
    assert.equal(downloaded.status, 200); assert.equal(await downloaded.text(), content);
    storageVerified = true;
  }
  finished = true;
} finally {
  const failures = [];
  for (const id of resources.reverse()) {
    try {
      const row = await context.resources.get(id), actor = { id: row.owner_id };
      if (row.kind === 'object') await context.objects.remove(actor, row);
      else await context.resources.delete(actor, row);
    }
    catch (error) { failures.push(error); }
  }
  if (!failures.length) {
    const ids = identities.map(value => typeof value === 'string' ? value : value.id);
    await cleanupIdentities(context.db, ids);
  }
  await context.db.close(); await rm(directory, { recursive: true, force: true });
  if (failures.length) throw new AggregateError(failures, 'Release verification cleanup failed.');
}
assert.equal(finished, true);
console.log(JSON.stringify({ verified: true, publicUrl: true, database: true, storage: storageVerified, exec: true, keyRotation: true, confirmation: true, cleanup: true }));
