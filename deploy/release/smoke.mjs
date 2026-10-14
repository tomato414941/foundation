import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { configuration } from '../../dist/server/config.js';
import { createContext } from '../../dist/server/context.js';
import { Client } from '../../dist/cli/src/client.js';
import { saveIdentity } from '../../dist/cli/src/config.js';
import { newIdentityKeys, publicPart, bindKeys, signBinding, canonical } from '../../dist/shared/authority.js';
import { CustodyClient } from '../../dist/shared/client.js';
import { FunctionClient } from '../../dist/shared/function-client.js';
import { FileJournal } from '../../dist/runtime/journal.js';
import { JournalTrust } from '../../dist/runtime/trust.js';
import { ContentTypes } from '../../dist/shared/custody.js';
import { encode, decode } from '../../dist/shared/encryption.js';
import { cleanupIdentities } from './cleanup.mjs';

// Only disposable identities and test material are used, including against production.
const config = await configuration();
const context = await createContext(config);
const directory = await mkdtemp(join(tmpdir(), 'foundation-release-smoke-'));
const identities = [], resources = [];
let environment, agent, mcp, finished = false;
const check = async path => {
  const response = await fetch(config.origin + path, { signal: AbortSignal.timeout(30_000), redirect: 'error' });
  assert.equal(response.status, 200, 'Public request failed: ' + path);
  return response;
};
const wait = async (read, ready, seconds = 240) => {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) { const value = await read(); if (ready(value)) return value; await delay(1500); }
  throw new Error('Release verification timed out.');
};
try {
  assert.equal((await (await check('/health')).json()).ok, true);
  const html = await (await check('/signin')).text();
  assert.ok(html.includes('/assets/'), 'The sign-in page must load its built assets.');
  const asset = html.match(/(?:src|href)="(\/assets\/[^"<>]+\.(?:js|css))"/);
  assert.ok(asset); await check(asset[1]);
  for (let index = 0; index < 2; index++) {
    const keys = await newIdentityKeys();
    const enrollment = await context.authentication.enroll('Release verification ' + crypto.randomUUID(), publicPart(keys.encryption));
    identities.push(enrollment.principal.id);
    const binding = bindKeys(enrollment.principal.id, keys);
    const client = new Client({ origin: config.origin, principalId: enrollment.principal.id, token: enrollment.token, keys, binding });
    await client.json('/api/principals/' + binding.principalId + '/binding', { method: 'PUT', body: await signBinding(binding, keys) });
    const trust = new JournalTrust(new FileJournal(join(directory, String(index)), config.origin, binding, keys));
    const custody = new CustodyClient(client, config.origin, binding, keys, trust);
    const functions = new FunctionClient(client, custody);
    identities[index] = { id: binding.principalId, client, custody, functions, binding, trust };
  }
  const [owner, caller] = identities;
  if (process.env.RELEASE_SMOKE_MODE === 'attached') {
    const home = join(directory, 'agent');
    process.env.XDG_CONFIG_HOME = home;
    await saveIdentity(owner.client.identity);
    environment = crypto.randomUUID();
    agent = spawn(process.execPath, ['/app/release/cli.mjs', 'agent', 'start', '--id', environment, '--isolation', 'process'],
      { env: { ...process.env, XDG_CONFIG_HOME: home }, stdio: 'ignore' });
  } else {
    const created = await owner.client.json('/api/principals/' + owner.id + '/resources', { method: 'POST', body: {
      kind: 'environment', name: 'Release verification', options: { lifetime: { idleSeconds: 300, maxSeconds: 600 } },
    } });
    environment = created.id;
  }
  const registration = await wait(async () => {
    try { return await owner.client.json('/api/environments/' + environment + '/registration'); }
    catch (error) { if (error.status === 404 || error.status === 409) return { registration: null }; throw error; }
  }, value => Boolean(value.registration));
  const executor = registration.registration.manifest.executor;
  if (!identities.some(value => value.id === executor.principalId)) identities.push(executor.principalId);
  // Trust only the disposable executor enrolled for this verification environment.
  const physical = await context.bindings.current(executor.principalId);
  assert.equal(canonical(physical.binding), canonical(executor));
  await owner.trust.rememberBinding(executor); await caller.trust.rememberBinding(executor);
  await caller.trust.rememberBinding(owner.binding);
  const secret = 'release-input-' + crypto.randomUUID();
  const input = await owner.custody.save('Release input', encode(secret), await owner.custody.policy(owner.id, ContentTypes.value));
  resources.push(input.id);
  const definition = {
    description: '', program: { kind: 'command', command: ['node', '-e',
      'let s="";process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>console.log(JSON.stringify({arguments:JSON.parse(s),configured:!!process.env.TOKEN,output:require("crypto").randomBytes(24).toString("hex")})));'],
      inputs: [{ name: 'TOKEN', source: { id: input.id } }], timeoutSeconds: 90 },
    parameters: [{ name: 'count', label: 'Count', type: 'number', required: true }, { name: 'enabled', label: 'Enabled', type: 'boolean', required: true }], result: 'json',
  };
  const fn = await owner.functions.save({ ownerId: owner.id, name: 'Release function', definition });
  resources.push(fn.id);
  await owner.functions.configure(fn.id, { environmentId: environment });
  await owner.client.json('/api/relations', { method: 'POST', body: { subjectId: caller.id, relation: 'runner', objectId: fn.id } });
  await assert.rejects(caller.custody.read(input.id));
  const arguments_ = { count: 0, enabled: false };
  const publicFunctions = new FunctionClient(caller.client);
  const interface_ = await publicFunctions.get(fn.id);
  assert.deepEqual(Object.keys(interface_.data).sort(), ['description', 'parameters', 'result']);
  mcp = new McpClient({ name: 'Foundation release verification', version: '1.0.0' });
  await mcp.connect(new StreamableHTTPClientTransport(new URL('/api/mcp', config.origin), {
    requestInit: { headers: { authorization: 'Bearer ' + caller.client.identity.token } },
  }));
  const call = async (name, arguments__) => {
    const response = await mcp.callTool({ name, arguments: arguments__ });
    assert.notEqual(response.isError, true, 'The MCP function operation failed.');
    return response.structuredContent.data;
  };
  const available = await call('foundation_functions', { query: 'Release function' });
  assert.ok(available.body.items.some(item => item.id === fn.id));
  const started = (await call('foundation_invoke_function', { functionId: fn.id, arguments: arguments_ })).body;
  const result = await wait(() => call('foundation_execution_result', { id: started.id }),
    value => !['waiting', 'running'].includes(value.state));
  const returned = JSON.parse(result.text)[0];
  assert.equal(result.state, 'succeeded'); assert.deepEqual(returned.arguments, arguments_); assert.equal(returned.configured, true);
  assert.ok(!JSON.stringify(result).includes(secret));
  const capture = await caller.functions.invoke(fn.id, arguments_, { save: { '/output': 'Release output' } });
  const captured = await wait(() => caller.functions.result(capture.id), value => !['waiting', 'running'].includes(value.state));
  assert.equal(captured.state, 'succeeded'); assert.deepEqual(Object.keys(captured.results[0]), ['saved']);
  const output = captured.results[0].saved['Release output']; resources.push(output);
  assert.match(decode(await caller.custody.reveal(output)), /^[a-f0-9]{48}$/);
  finished = true;
} finally {
  const failures = [];
  if (mcp) await mcp.close();
  if (agent) {
    agent.kill('SIGTERM');
    await new Promise(resolve => { if (agent.exitCode !== null) resolve(); else agent.once('exit', resolve); });
  }
  for (const id of resources.reverse()) {
    try { await context.resources.delete({ id: (await context.resources.get(id)).owner_id }, await context.resources.get(id)); }
    catch (error) { failures.push(error); }
  }
  if (environment) {
    try {
      const row = await context.resources.get(environment);
      if (row.data.driver === 'attached') await context.resources.delete({ id: row.owner_id }, row);
      else {
        await context.environments.remove({ id: row.owner_id }, row);
        await wait(async () => {
        await context.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [environment]);
        await context.environments.tick();
        return context.environments.deletion({ id: row.owner_id }, environment);
        }, value => value.state === 'complete', 360);
      }
    } catch (error) { failures.push(error); }
  }
  if (!failures.length) {
    const ids = identities.map(value => typeof value === 'string' ? value : value.id);
    await cleanupIdentities(context.db, ids);
  }
  await context.db.close(); await rm(directory, { recursive: true, force: true });
  if (failures.length) throw new AggregateError(failures, 'Release verification cleanup failed.');
}
assert.equal(finished, true);
console.log(JSON.stringify({ verified: true, publicUrl: true, database: true, function: true, mcp: true, encryptedInputs: true, encryptedOutput: true, cleanup: true }));
