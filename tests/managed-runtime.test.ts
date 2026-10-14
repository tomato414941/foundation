import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { Client as McpClient } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { fixture } from './support.js';
import { sshFixture } from './ssh-support.js';
import { MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { CreatedProcess, ProcessView } from '../shared/process.js';
import type { ProcessRequest } from '../shared/process.js';
import { ManagedProcesses } from '../server/managed-processes.js';

test('API・MCP・SSHから同じVMのソフトウェアとファイルを使い、接続断から実行結果を回復する', async t => {
  const local = await sshFixture(t), runner = new MemoryRunner();
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included' });
  const c = await createContext(f.config, { db: f.db, runner, ssh: runner.ssh });
  const app = await buildApp(c), owner = await f.person(), other = await f.person('Other');
  const origin = await app.listen({ host: '127.0.0.1', port: 0 });
  const mcp = new McpClient({ name: 'ssh-environment-test', version: '1' });
  t.after(async () => { await mcp.close(); await app.close(); await f.close(); });
  const row = await c.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse({}));
  await c.environments.tick();
  t.mock.method(c.environments, 'connection', async () => local.destination);
  let worker = c.managedProcesses;
  Object.assign(worker, { runtime: local.runtime });
  const api = async (path: string, body?: unknown) => {
    const response = await app.inject({ method: body ? 'POST' : 'GET', url: path,
      headers: { authorization: 'Bearer ' + owner.token }, ...(body ? { payload: body } : {}) });
    assert.ok(response.statusCode < 400, response.body);
    return response.json();
  };
  const create = async (input: Partial<ProcessRequest> & Pick<ProcessRequest, 'command'>) => {
    const task = CreatedProcess.parse(await api('/api/environments/' + row.id + '/processes',
      { workingDirectory: local.directory, ...input }));
    local.ids.push(task.id);
    return task;
  };
  const finished = async (id: string) => {
    for (let attempt = 0; attempt < 100; attempt++) {
      await f.db.pool.query('UPDATE environment_processes SET lease_until=now() WHERE id=$1 AND lease_token IS NULL', [id]);
      await worker.tick();
      const result = ProcessView.parse(await api('/api/processes/' + id));
      if (result.finishedAt) return result;
      await delay(50);
    }
    throw new Error('The SSH process did not finish.');
  };
  const run = async (command: string[]) => {
    const result = await finished((await create({ command })).id);
    assert.equal(result.state, 'succeeded', JSON.stringify(result));
    return result;
  };
  await run(['/bin/sh', '-c', 'printf "#!/bin/sh\\nprintf installed" > program; chmod +x program; printf shared > saved.txt']);
  assert.equal((await run(['./program'])).result!.stdout, 'installed');
  assert.equal((await local.ssh.run(local.destination, 'cat ' + local.directory + '/saved.txt')).stdout, 'shared');
  await run([process.execPath, '-e',
    'const {spawn}=require("child_process");const code=\'require("http").createServer((_,r)=>r.end("service"))' +
    '.listen(0,"127.0.0.1",function(){require("fs").writeFileSync("service-port",String(this.address().port))})\';' +
    'spawn(process.execPath,["-e",code],{detached:true,stdio:"ignore"}).unref()']);
  for (let attempt = 0; ; attempt++) {
    try { assert.ok(Number(await readFile(join(local.directory, 'service-port'), 'utf8')) > 0); break; }
    catch (error) { if (attempt > 50) throw error; await delay(50); }
  }
  await mcp.connect(new StreamableHTTPClientTransport(new URL('/api/mcp', origin), {
    requestInit: { headers: { authorization: 'Bearer ' + owner.token } },
  }));
  const submitted = await mcp.callTool({ name: 'foundation_api', arguments: {
    method: 'POST', path: '/api/environments/' + row.id + '/processes', body: {
      workingDirectory: local.directory, command: [process.execPath, '-e',
        'const fs=require("fs");fetch("http://127.0.0.1:"+fs.readFileSync("service-port","utf8"))' +
        '.then(r=>r.text()).then(s=>console.log(fs.readFileSync("saved.txt","utf8")+";"+s))'],
    },
  } });
  assert.notEqual(submitted.isError, true, JSON.stringify(submitted));
  const created = submitted.structuredContent!.data as { status: number; body: { id: string } };
  assert.equal(created.status, 202); local.ids.push(created.body.id);
  assert.equal((await finished(created.body.id)).result!.stdout, 'shared;service\n');
  const recovery = await create({ command: ['/bin/sh', '-c', 'printf x >> once; sleep 1; printf recovered'] });
  const inspect = t.mock.method(local.runtime, 'inspect', async () => { throw new Error('Connection interrupted'); });
  await worker.tick();
  assert.equal((await api('/api/processes/' + recovery.id)).state, 'uncertain');
  inspect.mock.restore();
  worker = new ManagedProcesses(c.processes, c.environments);
  Object.assign(worker, { runtime: local.runtime });
  assert.equal((await finished(recovery.id)).result!.stdout, 'recovered');
  assert.equal(await readFile(join(local.directory, 'once'), 'utf8'), 'x');
  const cancelled = await create({ command: ['sleep', '30'] });
  const outage = t.mock.method(local.runtime, 'inspect', async () => { throw new Error('Connection interrupted'); });
  await worker.tick();
  assert.equal((await api('/api/processes/' + cancelled.id)).state, 'uncertain');
  outage.mock.restore();
  await api('/api/processes/' + cancelled.id + '/cancel', {});
  assert.equal((await finished(cancelled.id)).state, 'cancelled');
  const denied = await app.inject({ method: 'POST', url: '/api/environments/' + row.id + '/processes',
    headers: { authorization: 'Bearer ' + other.token }, payload: { command: ['true'] } });
  assert.equal(denied.statusCode, 403);
});
