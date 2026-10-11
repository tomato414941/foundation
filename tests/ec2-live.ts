import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { EC2Runner } from '../server/ec2-runner.js';
import { buildApp } from '../server/app.js';
import type { ResourceRow } from '../server/resources.js';

// Run against a disposable database schema and a public HTTPS test origin.
const origin = process.env.EC2_TEST_ORIGIN;
if (!origin || !process.env.EC2_ENVIRONMENT_AMI) throw new Error('Set EC2_TEST_ORIGIN and the EC2 environment configuration.');
const execute = promisify(execFile), directory = await mkdtemp(join(tmpdir(), 'foundation-ec2-live-'));
const f = await fixture({ ...Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => Boolean(entry[1]) &&
  (entry[0].startsWith('EC2_ENVIRONMENT_') || entry[0] === 'AWS_REGION' || entry[0] === 'ENVIRONMENT_COMMAND_IMAGE'))),
  FOUNDATION_ORIGIN: origin, FOUNDATION_BILLING_MODE: 'included', FOUNDATION_INCLUDED_ENVIRONMENTS: '10' });
const runner = new EC2Runner(f.config), c = await createContext(f.config, { db: f.db, runner }), app = await buildApp(c);
const rows: ResourceRow[] = [], failures: unknown[] = [];
const key = join(directory, 'key'), known = join(directory, 'known_hosts');
await execute('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
const publicKey = (await readFile(key + '.pub', 'utf8')).trim();
const wait = async <T>(read: () => Promise<T>, ready: (value: T) => boolean): Promise<T> => {
  for (let attempt = 0; attempt < 180; attempt++) { const value = await read(); if (ready(value)) return value; await delay(5_000); }
  throw new Error('The environment did not finish the operation.');
};
const owners = [await f.person('EC2 test owner A'), await f.person('EC2 test owner B')];
const api = async (method: string, path: string, owner: typeof owners[number], body?: unknown) => {
  const result = await app.inject({ method: method as 'GET' | 'POST', url: path,
    headers: { authorization: 'Bearer ' + owner.token }, ...(body === undefined ? {} : { payload: body as any }) });
  assert.ok(result.statusCode < 400, result.body);
  return result.json();
};
const ssh = (host: string, command: string) => execute('ssh', ['-i', key, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
  '-o', 'UserKnownHostsFile=' + known, '-o', 'ConnectTimeout=15', 'root@' + host, command], { timeout: 45_000 });
try {
  await app.listen({ host: '127.0.0.1', port: Number(process.env.EC2_TEST_PORT ?? '3461') });
  for (const owner of [owners[0]!, owners[0]!, owners[1]!]) {
    const result = await api('POST', '/api/principals/' + owner.actor.id + '/resources', owner, { kind: 'environment',
      options: { lifetime: { idleSeconds: 900, maxSeconds: 1800 }, ssh: { authorizedKeys: [publicKey] } } });
    rows.push(await c.resources.get(result.id));
    await c.environments.tick();
  }
  const connections = [];
  for (const row of rows) {
    const connection = await wait(() => c.environments.ssh({ id: row.owner_id }, row.id), value => value?.state === 'ready');
    assert.ok(connection?.host && connection.hostKey);
    connections.push(connection);
    await writeFile(known, connections.map(value => value.host + ' ' + value.hostKey).join('\n') + '\n', { mode: 0o600 });
    console.log('SSH ready: ' + row.id + ' ' + connection.host + ':22');
  }
  const jobs = await f.db.all<{ machine_id: string }>('SELECT machine_id FROM environment_jobs');
  const instances = (await runner.client.send(new DescribeInstancesCommand({ InstanceIds: jobs.map(job => job.machine_id) }))).Reservations?.flatMap(row => row.Instances ?? []) ?? [];
  assert.equal(new Set(instances.map(value => value.SubnetId)).size, 3);
  for (const [index, row] of rows.entries()) {
    const host = connections[index]!.host!;
    assert.equal((await ssh(host, 'printf env-' + index + ' > /workspace/marker.txt; cat /workspace/marker.txt')).stdout, 'env-' + index);
    const owner = owners.find(value => value.actor.id === row.owner_id)!;
    const started = await api('POST', '/api/environments/' + row.id + '/processes', owner,
      { command: ['sh', '-c', 'cat marker.txt; printf api-' + index + ' > api.txt'], workingDirectory: '/workspace' });
    const completed = await wait(() => api('GET', '/api/processes/' + started.id, owner), value => !['queued', 'running'].includes(value.state));
    assert.equal(completed.state, 'succeeded', JSON.stringify(completed));
    assert.equal(completed.result.stdout, 'env-' + index);
    assert.equal((await ssh(host, 'cat /workspace/api.txt')).stdout, 'api-' + index);
    const otherInstances = instances.filter(value => value.PublicIpAddress !== host);
    for (const target of otherInstances) {
      const probe = 'timeout 3 bash -c ' + JSON.stringify('echo > /dev/tcp/' + target.PrivateIpAddress + '/22') +
        '; status=$?; test "$status" -eq 124 && printf blocked';
      assert.equal((await ssh(host, probe)).stdout, 'blocked');
    }
    const platformProbe = 'timeout 3 bash -c "echo > /dev/tcp/10.42.1.253/80"; status=$?; test "$status" -eq 124 && printf blocked';
    assert.equal((await ssh(host, platformProbe)).stdout, 'blocked');
    const profile = await ssh(host, 'token=$(curl -fsS -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token);' +
      'curl -s -o /dev/null -w "%{http_code}" -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/');
    assert.equal(profile.stdout, '404');
  }
  console.log('Verified: three isolated VMs, SSH, API/workspace sharing, private network denial in both directions, and no guest AWS role.');
  await c.environments.stop({ id: rows[0]!.owner_id }, await c.resources.get(rows[0]!.id));
  await f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [rows[0]!.id]);
  await c.environments.tick();
  const machine = (await runner.find(rows[0]!.id))!;
  const state = (await runner.client.send(new DescribeInstancesCommand({ InstanceIds: [machine] }))).Reservations?.[0]?.Instances?.[0]?.State?.Name;
  assert.equal(state, 'stopped');
  assert.ok(await runner.findVolume(rows[0]!.id));
  console.log('Verified: stop retains the instance and its encrypted disk.');
} catch (error) { failures.push(error); }
finally {
  for (const row of rows) {
    try {
      await c.environments.remove({ id: row.owner_id }, await c.resources.get(row.id));
      for (let attempt = 0; attempt < 5; attempt++) {
        await f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [row.id]);
        await c.environments.tick();
        const result = await c.environments.deletion({ id: row.owner_id }, row.id);
        if (result.state === 'complete') break;
        if (result.state === 'failed') await c.environments.remove({ id: row.owner_id }, await c.resources.get(row.id));
        await delay(5_000);
      }
      assert.equal((await c.environments.deletion({ id: row.owner_id }, row.id)).state, 'complete');
      assert.equal(await runner.find(row.id), null);
      assert.equal(await runner.findVolume(row.id), null);
    } catch (error) { failures.push(error); }
  }
  await app.close();
  await f.close();
  await rm(directory, { recursive: true, force: true });
}
if (failures.length) throw new AggregateError(failures, 'Live EC2 verification failed.');
console.log('Verified: deletion completed and all test instances, disks, and per-environment networks were removed.');
