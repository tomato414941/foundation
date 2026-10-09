import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration } from '../server/config.js';
import { FlyRunner } from '../server/runner.js';
import { EnvironmentInput } from '../shared/contracts.js';

test('Flyの命名制約に従って実行環境を起動し、再試行時に同じボリュームを使用する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-runner-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = await configuration({ DATABASE_URL: 'postgres://localhost/foundation',
    FOUNDATION_DATA: directory, FOUNDATION_KEY: Buffer.alloc(32).toString('base64url'),
    FLY_API_TOKEN: 'test-token', FLY_APP: 'test-app',
    FLY_IMAGE: 'ghcr.io/example/agent@sha256:' + '1'.repeat(64) });
  const volumes: Array<{ id: string; name: string; state: string }> = [];
  const machines: Array<{ id: string; name: string }> = [];
  t.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : null;
    if (path.endsWith('/volumes')) {
      if (init.method === 'POST') {
        if (!/^[a-z0-9_]{1,30}$/.test(body.name))
          return Response.json({ error: 'Invalid volume name' }, { status: 400 });
        volumes.push({ id: 'vol_test', name: body.name, state: 'created' });
        return Response.json(volumes.at(-1));
      }
      return Response.json(volumes);
    }
    assert.ok(path.endsWith('/machines'));
    if (init.method === 'POST') {
      assert.equal(body.config.mounts[0].volume, 'vol_test');
      machines.push({ id: 'machine-test', name: body.name });
      return Response.json(machines.at(-1));
    }
    return Response.json(machines);
  });
  const runner = new FlyRunner(config), options = EnvironmentInput.parse({});
  const created: Array<[string, string]> = [];
  for (let attempt = 0; attempt < 2; attempt++)
    assert.equal(await runner.start('53643106-91b3-442f-91e2-d91ae5a42d84', options, {},
      async (machine, volume) => { created.push([machine, volume]); }), 'machine-test');
  assert.equal(volumes.length, 1);
  assert.equal(machines.length, 1);
  assert.deepEqual(created, [['machine-test', 'vol_test'], ['machine-test', 'vol_test']]);
});

test('環境ごとの公開TCPポートを対応するSSHリスナーへ接続する', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-runner-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = await configuration({ DATABASE_URL: 'postgres://localhost/foundation',
    FOUNDATION_DATA: directory, FOUNDATION_KEY: Buffer.alloc(32).toString('base64url'),
    FLY_API_TOKEN: 'test-token', FLY_APP: 'test-app', FLY_IMAGE: 'ghcr.io/example/agent@sha256:' + '1'.repeat(64) });
  const endpoints = new Map<number, number>();
  t.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    if (init.method === 'GET') return Response.json([]);
    const body = JSON.parse(String(init.body));
    if (new URL(url).pathname.endsWith('/volumes')) return Response.json({ id: 'vol_' + body.name });
    for (const service of body.config.services) for (const external of service.ports) {
      assert.equal(service.protocol, 'tcp');
      assert.equal(service.autostop, false);
      endpoints.set(external.port, service.internal_port);
    }
    return Response.json({ id: body.name });
  });
  const runner = new FlyRunner(config);
  for (const port of [24000, 24001]) await runner.start(crypto.randomUUID(), EnvironmentInput.parse({}),
    { FOUNDATION_SSH_PORT: String(port) }, async () => {});
  assert.deepEqual([...endpoints], [[24000, 24000], [24001, 24001]]);
});
