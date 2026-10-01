import test from 'node:test';
import assert from 'node:assert/strict';
import { FlyRunner } from '../src/runners/fly.mjs';

// Fly's Machines API as far as the runner uses it: make a machine, wait for it, run short commands in it (with no
// standard input, as Fly's exec has none), destroy it. The machine's shell is played by what each call is labelled.
function fakeFly() {
  const calls = [], machines = new Map();
  const answer = (status, value) => new Response(value === undefined ? '' : JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  const ok = (stdout = '', exit_code = 0) => answer(200, { exit_code, stdout, stderr: '' });
  const fetcher = async (url, init) => {
    const { pathname, search } = new URL(url), body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path: pathname + search, body, authorization: init.headers.authorization });
    const [, , , app, , id, action] = pathname.split('/');
    if (app !== 'runners') return answer(404, { error: 'no app' });
    if (init.method === 'POST' && !id) { machines.set('m1', { files: new Map() }); return answer(200, { id: 'm1', state: 'created' }); }
    const machine = machines.get(id);
    if (!machine) return answer(404, { error: 'not found' });
    if (init.method === 'GET' && action === 'wait') return answer(200, { ok: true });
    if (init.method === 'DELETE') { machines.delete(id); return answer(200, { ok: true }); }
    const [, , , label, first, ...rest] = body.command;
    if (label === 'put') { machine.files.set(first, Buffer.from(rest[0], 'base64').toString()); return ok(); }
    if (label === 'start') {
      const input = machine.files.get(first + '/stdin') ?? '';
      machine.files.set(first + '/stdout', 'ran ' + rest.join(' ') + (input ? ' <' + input : ''));
      machine.files.set(first + '/code', '4');
      return ok();
    }
    if (label === 'look') return machine.files.has(first + '/code') ? ok(machine.files.get(first + '/code')) : ok('', 1);
    if (label === 'collect') return ok(['stdout', 'stderr', 'code'].map(part => Buffer.from(machine.files.get(first + '/' + part) ?? '').toString('base64')).join('\n') + '\n');
    return ok();
  };
  return { calls, machines, fetcher };
}

test('Fly の実行基盤は、使い捨てのマシンを作り、中で標準入力つきのコマンドを動かして結果を集め、消す', async () => {
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
  assert.equal(ran.exitCode, 4); assert.equal(ran.stdout.toString(), 'ran echo hi <input'); assert.equal(ran.timedOut, false);
  assert.ok(fly.calls.every(call => !call.body || call.body.stdin === undefined), 'standard input goes in as a file, since Fly\'s exec carries none');
  await runner.put('m1', '.foundation/key', 'fdn_secret\n');
  assert.equal(fly.machines.get('m1').files.get('.foundation/key'), 'fdn_secret\n');
  await runner.stop('m1');
  assert.equal(fly.machines.has('m1'), false);
  await runner.stop('m1');
});

function scriptedFly(steps) {
  const calls = [];
  const fetcher = async (url, init) => {
    const step = steps[calls.length];
    calls.push({ method: init.method, path: new URL(url).pathname + new URL(url).search });
    assert.ok(step, 'no unexpected provider call');
    assert.equal(init.method, step.method);
    if (step.path) assert.equal(calls.at(-1).path, '/v1/apps/runners' + step.path);
    step.check?.();
    if (step.error) throw step.error;
    return new Response(JSON.stringify(step.body ?? {}), { status: step.status ?? 200 });
  };
  const runner = new FlyRunner({ token: 'fly-token', app: 'runners', image: 'registry.fly.io/runners:1', fetcher });
  return { runner, calls };
}

test('Fly の削除が失敗したときは、機械が止まったとは答えない', async t => {
  for (const failure of [
    { status: 503 },
    { status: 401 },
    { error: new Error('connection failed') },
    { error: new DOMException('request timed out', 'TimeoutError') },
  ]) await t.test(String(failure.status ?? failure.error.name), async () => {
    const { runner, calls } = scriptedFly([{ method: 'DELETE', path: '/machines/m1?force=true', ...failure }]);
    await assert.rejects(runner.stop('m1'), { code: 'runner_unavailable' });
    assert.equal(calls.length, 1);
  });
});

test('Fly の機械が既に消えていれば、何度閉じても成功する', async () => {
  const { runner, calls } = scriptedFly([
    { method: 'DELETE', path: '/machines/m1?force=true', status: 404 },
    { method: 'DELETE', path: '/machines/m1?force=true', status: 404 },
  ]);
  await runner.stop('m1');
  await runner.stop('m1');
  assert.equal(calls.length, 2);
});

test('Fly が削除を受け付けても、まだ存在する機械の終了は確定しない', async t => {
  for (const state of ['started', 'stopping', 'stopped', undefined]) await t.test(String(state), async () => {
    const { runner, calls } = scriptedFly([
      { method: 'DELETE', path: '/machines/m1?force=true', status: 202 },
      { method: 'GET', path: '/machines/m1', body: state ? { state } : {} },
    ]);
    await assert.rejects(runner.stop('m1'), { code: 'runner_unavailable' });
    assert.equal(calls.length, 2);
  });
});

test('Fly の削除後の照会で消失または破棄済みを確認できれば終了する', async t => {
  for (const final of [{ status: 404 }, { body: { state: 'destroyed' } }]) await t.test(String(final.status ?? final.body.state), async () => {
    const { runner, calls } = scriptedFly([
      { method: 'DELETE', path: '/machines/m1?force=true', status: 202 },
      { method: 'GET', path: '/machines/m1', ...final },
    ]);
    await runner.stop('m1');
    assert.equal(calls.length, 2);
  });
});

test('Fly の削除後の照会が失敗したときも、終了を確定しない', async t => {
  for (const failure of [
    { status: 503 },
    { error: new Error('connection failed') },
    { error: new DOMException('request timed out', 'TimeoutError') },
  ]) await t.test(String(failure.status ?? failure.error.name), async () => {
    const { runner, calls } = scriptedFly([
      { method: 'DELETE', path: '/machines/m1?force=true' },
      { method: 'GET', path: '/machines/m1', ...failure },
    ]);
    await assert.rejects(runner.stop('m1'), { code: 'runner_unavailable' });
    assert.equal(calls.length, 2);
  });
});

test('Fly の機械 ID は起動待ちより先に渡され、起動待ちが失敗しても失われない', async t => {
  for (const wait of [{}, { status: 503 }, { error: new DOMException('request timed out', 'TimeoutError') }])
    await t.test(String(wait.status ?? wait.error?.name ?? 'success'), async () => {
      const allocated = [];
      const { runner, calls } = scriptedFly([
        { method: 'POST', path: '/machines', body: { id: 'm1' } },
        { method: 'GET', path: '/machines/m1/wait?state=started&timeout=60',
          check: () => assert.deepEqual(allocated, ['m1'], 'allocation is recorded before waiting on the machine'), ...wait },
      ]);
      const started = runner.start({ id: 'env-1', onCreated: machine => { allocated.push(machine); } });
      if (wait.status || wait.error) await assert.rejects(started, { code: 'runner_unavailable' });
      else assert.equal((await started).machine, 'm1');
      assert.deepEqual(allocated, ['m1']);
      assert.equal(calls.length, 2);
    });
});

test('Fly の作成拒否と、作成結果が不明な失敗を区別する', async t => {
  for (const status of [400, 401, 402, 403, 404, 422, 429, 408, 409, 500, 503]) await t.test(String(status), async () => {
    const runner = new FlyRunner({ token: 'fake', app: 'runners', image: 'image', fetcher: async () => new Response('{}', { status }) });
    await assert.rejects(runner.start({ id: 'env' }), error => {
      assert.equal(Boolean(error.notCreated), [400, 401, 402, 403, 404, 422, 429].includes(status)); return true;
    });
  });
  const runner = new FlyRunner({ token: 'fake', app: 'runners', image: 'image', fetcher: async () => { throw new Error('network'); } });
  await assert.rejects(runner.start({ id: 'env' }), error => { assert.equal(error.notCreated, undefined); return true; });
});
