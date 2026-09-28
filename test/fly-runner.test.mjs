import test from 'node:test';
import assert from 'node:assert/strict';
import { FlyRunner } from '../src/runners/fly.mjs';

// Fly's Machines API as far as the runner uses it: make a machine, wait for it, run commands in it, destroy it.
function fakeFly() {
  const calls = [], machines = new Map();
  const answer = (status, value) => new Response(value === undefined ? '' : JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  const fetcher = async (url, init) => {
    const { pathname } = new URL(url), body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path: pathname + new URL(url).search, body, authorization: init.headers.authorization });
    const [, , , app, , id, action] = pathname.split('/');
    if (app !== 'runners') return answer(404, { error: 'no app' });
    if (init.method === 'POST' && !id) { machines.set('m1', { files: new Map() }); return answer(200, { id: 'm1', state: 'created' }); }
    const machine = machines.get(id);
    if (!machine) return answer(404, { error: 'not found' });
    if (init.method === 'GET' && action === 'wait') return answer(200, { ok: true });
    if (init.method === 'POST' && action === 'exec') {
      const [program, , script, , path, encoded] = body.command;
      if (program === 'sh' && script.includes('base64 -d')) { machine.files.set(path, Buffer.from(encoded, 'base64').toString()); return answer(200, { exit_code: 0, stdout: '', stderr: '' }); }
      return answer(200, { exit_code: 0, stdout: 'ran ' + body.command.join(' ') + (body.stdin ? ' <' + body.stdin : ''), stderr: '' });
    }
    if (init.method === 'DELETE') { machines.delete(id); return answer(200, { ok: true }); }
    return answer(400, {});
  };
  return { calls, machines, fetcher };
}

test('Fly の実行基盤は、使い捨てのマシンを作り、コマンドを動かし、ファイルを置き、消す', async () => {
  const fly = fakeFly(), runner = new FlyRunner({ token: 'fly-token', app: 'runners', image: 'registry.fly.io/runners:1', fetcher: fly.fetcher });
  const started = await runner.start({ id: 'env-1', size: 'medium', env: { FOUNDATION_URL: 'https://example.test', FOUNDATION_RUNTIME_KEY_FILE: '~/.foundation/key' } });
  assert.equal(started.machine, 'm1');
  const made = fly.calls[0];
  assert.equal(made.authorization, 'Bearer fly-token');
  assert.equal(made.body.region, 'nrt');
  assert.equal(made.body.config.image, 'registry.fly.io/runners:1');
  assert.equal(made.body.config.auto_destroy, true);
  assert.deepEqual(made.body.config.guest, { cpu_kind: 'shared', cpus: 2, memory_mb: 1024 });
  assert.equal(made.body.config.env.FOUNDATION_RUNTIME_KEY_FILE, '/root/.foundation/key', 'a path under home is placed under the machine\'s home');
  assert.match(fly.calls[1].path, /\/machines\/m1\/wait\?state=started/);
  const ran = await runner.exec('m1', { command: ['echo', 'hi'], stdin: 'input', timeoutMs: 5000 });
  assert.equal(ran.exitCode, 0); assert.equal(ran.stdout.toString(), 'ran echo hi <input');
  await runner.put('m1', '.foundation/key', 'fdn_secret\n');
  assert.equal(fly.machines.get('m1').files.get('.foundation/key'), 'fdn_secret\n');
  assert.doesNotMatch(JSON.stringify(fly.calls.at(-1).body), /fdn_secret/, 'the machine writes the file itself from what it is handed');
  await runner.stop('m1');
  assert.equal(fly.machines.has('m1'), false);
  await runner.stop('m1');
});
