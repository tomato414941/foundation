import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, readFile, symlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { fixture } from './support.js';
import { MemoryRunner } from './fakes.js';
import { MemoryJournal } from './delegation-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { CustodyClient } from '../shared/client.js';
import { Client } from '../cli/src/client.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { CreatedProcess, ProcessView } from '../shared/process.js';
import { Task } from '../shared/runtime-protocol.js';
import { JournalTrust } from '../runtime/trust.js';
import { childEnvironment } from '../runtime/command.js';

test('管理環境のAPIとMCPで同じソフトウェアを使い、コマンド終了後も起動したサービスを利用する', async t => {
  const reserved = createServer();
  await new Promise<void>(resolve => reserved.listen(0, '127.0.0.1', resolve));
  const port = (reserved.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => reserved.close(error => error ? reject(error) : resolve()));
  const origin = 'http://127.0.0.1:' + port;
  const f = await fixture({ FOUNDATION_ORIGIN: origin, FOUNDATION_BILLING_MODE: 'included',
    ENVIRONMENT_FUNCTION_IMAGE: process.env.TEST_COMMAND_IMAGE ??
      'node@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8' });
  const runner = new MemoryRunner(), context = await createContext(f.config, { db: f.db, runner });
  const app = await buildApp(context), owner = await f.person();
  let worker: ReturnType<typeof spawn> | undefined, finished: Promise<void> | undefined, servicePid: number | undefined;
  const mcp = new McpClient({ name: 'managed-environment-test', version: '1' });
  t.after(async () => {
    await mcp.close();
    if (servicePid) try { process.kill(servicePid, 'SIGKILL'); } catch { /* The service may have exited. */ }
    if (worker) {
      worker.kill('SIGTERM');
      const timeout = setTimeout(() => worker!.kill('SIGKILL'), 2000);
      try { await finished; } finally { clearTimeout(timeout); }
    }
    await app.close();
    await f.close();
  });
  await app.listen({ host: '127.0.0.1', port });
  const row = await context.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse({}));
  await context.environments.tick();
  const input = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(
    runner.machines.get(row.id)!.environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
  // The test worker shares the test host, whose SSH listener is exercised separately.
  const { ssh: _ssh, ...bootstrap } = input;
  const programs = join(f.config.dataDirectory, 'bin');
  await mkdir(programs);
  await symlink(process.execPath, join(programs, 'node'));
  await symlink('/usr/bin/flock', join(programs, 'flock'));
  worker = spawn(process.execPath, [resolve('cli/dist/cli.mjs'), 'agent', 'managed'], {
    env: childEnvironment({ PATH: programs, XDG_CONFIG_HOME: join(f.config.dataDirectory, 'runtime'), AWS_EC2_METADATA_DISABLED: 'true',
      FOUNDATION_EXECUTOR_BOOTSTRAP: Buffer.from(JSON.stringify(bootstrap)).toString('base64url') }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = '';
  worker.stdout!.resume();
  worker.stderr!.on('data', chunk => { errors += chunk; });
  finished = new Promise<void>(resolve => worker!.once('close', () => resolve()));
  const wait = async <T>(read: () => Promise<T>, ready: (value: T) => boolean): Promise<T> => {
    for (let attempt = 0; attempt < 300; attempt++) {
      assert.equal(worker!.exitCode, null, errors);
      const value = await read();
      if (ready(value)) return value;
      await delay(50);
    }
    throw new Error('The environment did not complete the operation. ' + errors);
  };
  await wait(() => context.resources.get(row.id), resource => Boolean(resource.data.processes));
  const api = new Client({ origin, token: owner.token, principalId: owner.actor.id, keys: owner.keys, binding: owner.binding });
  const run = async (command: string[]) => {
    const started = await api.json('/api/environments/' + row.id + '/processes', { method: 'POST', body: { command } }, CreatedProcess);
    const result = await wait(() => api.json('/api/processes/' + started.id, {}, ProcessView), value =>
      !['queued', 'running'].includes(value.state));
    assert.equal(result.state, 'succeeded', JSON.stringify(result));
    return result;
  };
  const executable = join(f.config.dataDirectory, 'installed-program');
  await run(['node', '-e', 'require("fs").writeFileSync(process.argv[1],"#!/bin/sh\\nprintf installed",{mode:0o700});' +
    'require("fs").writeFileSync("saved.txt","shared workspace")', executable]);
  assert.equal((await run([executable])).result!.stdout, 'installed');
  const environment = (await context.delegation.environment(row.id)).registration;
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(environment.manifest.executor);
  const custody = new CustodyClient(api, origin, owner.binding, owner.keys, trust);
  const task = await custody.submit(owner.actor.id, row.id, { kind: 'command', command: [executable], inputs: [], timeoutSeconds: 10 });
  const completed = await wait(() => api.json('/api/runtime/runs/' + task.id, {}, Task), value =>
    !['queued', 'running'].includes(value.state));
  const protectedResult = await custody.result(completed);
  assert.equal(protectedResult.ok, true);
  assert.equal((protectedResult.result as { stdout: string }).stdout, 'installed');
  const service = await run(['node', '-e',
    'const fs=require("fs"),{spawn}=require("child_process");' +
    'const code=\'require("http").createServer((_,res)=>res.end("service stays running"))' +
      '.listen(0,"127.0.0.1",function(){require("fs").writeFileSync("service-port",String(this.address().port))})\';' +
    'const child=spawn(process.execPath,["-e",code],{detached:true,stdio:"ignore"});child.unref();console.log(child.pid)']);
  servicePid = Number(service.result!.stdout.trim());
  assert.ok(Number.isSafeInteger(servicePid) && servicePid > 0);
  await wait(async () => {
    try { return Number(await readFile(join(service.workingDirectory, 'service-port'), 'utf8')); } catch { return 0; }
  }, value => value > 0);
  await mcp.connect(new StreamableHTTPClientTransport(new URL('/api/mcp', origin), {
    requestInit: { headers: { authorization: 'Bearer ' + owner.token } },
  }));
  const submitted = await mcp.callTool({ name: 'foundation_api', arguments: {
    method: 'POST', path: '/api/environments/' + row.id + '/processes', body: { command: ['node', '-e',
      'const fs=require("fs");fetch("http://127.0.0.1:"+fs.readFileSync("service-port","utf8"))' +
      '.then(r=>r.text()).then(text=>console.log(fs.readFileSync("saved.txt","utf8")+";"+text))'] },
  } });
  assert.notEqual(submitted.isError, true, JSON.stringify(submitted));
  const created = submitted.structuredContent!.data as { status: number; body: { id: string } };
  assert.equal(created.status, 202);
  const result = await wait(() => api.json('/api/processes/' + created.body.id, {}, ProcessView), value =>
    !['queued', 'running'].includes(value.state));
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  assert.equal(result.result!.stdout, 'shared workspace;service stays running\n');
});
