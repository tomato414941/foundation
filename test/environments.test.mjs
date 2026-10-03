import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { fixture, USER_A } from './helpers.mjs';
import { LocalRunner } from '../src/runners/local.mjs';

const CLI = fileURLToPath(new URL('../cli/runtime.mjs', import.meta.url));
const node = (...code) => [process.execPath, '-e', code.join('\n')];
const lent = (t, options = {}) => fixture(t, { runner: new LocalRunner(), ...options });

test('環境は何の ID も持たずに開き、コマンドを動かしても Foundation には届かない', async t => {
  const f = await lent(t), agent = await f.issueKey();
  const opened = await f.request('/v1/environments', { method: 'POST', token: agent.token, data: { name: 'scratch' } });
  assert.equal(opened.status, 201, opened.text);
  const environment = opened.json.environment;
  assert.equal(environment.kind, 'environment'); assert.equal(environment.identity, null); assert.equal(environment.owner_id, USER_A);
  const ran = await f.request('/v1/environments/' + environment.id + '/commands', { method: 'POST', token: agent.token,
    data: { command: node("const fs = require('node:fs');", "console.log('sum', 1 + 2, fs.existsSync(process.env.FOUNDATION_RUNTIME_KEY_FILE));") } });
  assert.equal(ran.status, 200, ran.text);
  assert.equal(ran.json.command.exit_code, 0); assert.equal(ran.json.command.stdout.trim(), 'sum 3 false');
  const cli = await f.request('/v1/environments/' + environment.id + '/commands', { method: 'POST', token: agent.token, data: { command: [process.execPath, CLI, 'api', 'GET', '/v1/principals/me'] } });
  assert.notEqual(cli.json.command.exit_code, 0, 'no key, no Foundation');
  assert.deepEqual((await f.request('/v1/resources?kind=environment', { token: agent.token })).json.resources.map(row => row.id), [environment.id]);
});

test('ID を付けた環境は、その principal として動き、渡した値は出力から伏せられ、閉じると鍵が失効する', async t => {
  const f = await lent(t), agent = await f.issueKey();
  await f.request('/v1/resources?kind=secret&name=token', { method: 'PUT', raw: 'kept-secret-value', type: 'text/plain' });
  const opened = await f.request('/v1/environments', { method: 'POST', token: agent.token, data: { identity: USER_A } });
  assert.equal(opened.status, 201, opened.text);
  const id = opened.json.environment.id;
  assert.equal(opened.json.environment.identity, USER_A);
  const me = await f.request('/v1/environments/' + id + '/commands', { method: 'POST', token: agent.token, data: { command: [process.execPath, CLI, 'api', 'GET', '/v1/principals/me'] } });
  assert.equal(me.json.command.exit_code, 0, me.json.command.stderr);
  assert.equal(JSON.parse(me.json.command.stdout).principal.id, USER_A);
  const printed = await f.request('/v1/environments/' + id + '/commands', { method: 'POST', token: agent.token,
    data: { command: [process.execPath, CLI, 'exec', 'TOKEN=token', '--', ...node('console.log(process.env.TOKEN)')] } });
  assert.equal(printed.json.command.exit_code, 0, printed.json.command.stderr);
  assert.equal(printed.json.command.stdout.trim(), '[redacted]');
  const keys = () => f.app.principals.keys(USER_A).filter(row => row.environment_id === id);
  assert.equal(keys().length, 1);
  assert.equal((await f.request('/v1/environments/' + id, { method: 'DELETE', token: agent.token, data: {} })).status, 200);
  assert.equal(keys().length, 0);
  assert.equal((await f.request('/v1/environments/' + id, { token: agent.token })).status, 404);
});

test('付けられる ID は、付ける者がその principal として動けるものだけで、外すと中の鍵は効かなくなる', async t => {
  const f = await lent(t), agent = await f.issueKey();
  const stranger = (await f.request('/v1/credentials', { method: 'POST', anonymous: true, data: { kind: 'key', name: 'someone else' } })).json.principal;
  assert.equal((await f.request('/v1/environments', { method: 'POST', token: agent.token, data: { identity: stranger.id } })).status, 403);
  const opened = (await f.request('/v1/environments', { method: 'POST', token: agent.token, data: { identity: agent.id } })).json.environment;
  assert.equal(opened.identity, agent.id);
  const removed = await f.request('/v1/environments/' + opened.id, { method: 'PATCH', token: agent.token, data: { identity: null } });
  assert.equal(removed.json.environment.identity, null);
  const after = await f.request('/v1/environments/' + opened.id + '/commands', { method: 'POST', token: agent.token, data: { command: [process.execPath, CLI, 'api', 'GET', '/v1/principals/me'] } });
  assert.notEqual(after.json.command.exit_code, 0);
});

test('一回の実行は、開いて動かして止め、結果を返す', async t => {
  const f = await lent(t), agent = await f.issueKey();
  const run = await f.request('/v1/runs', { method: 'POST', token: agent.token, data: { identity: USER_A, command: node("process.stdout.write('done'); process.exit(3)") } });
  assert.equal(run.status, 200, run.text);
  assert.equal(run.json.command.stdout, 'done'); assert.equal(run.json.command.exit_code, 3);
  assert.equal(run.json.environment.status, 'stopped');
  assert.deepEqual(f.app.principals.keys(USER_A).filter(row => row.environment_id === run.json.environment.id), []);
  const again = await f.request('/v1/environments/' + run.json.environment.id + '/commands/' + run.json.command.id, { token: agent.token });
  assert.equal(again.json.command.stdout, 'done');
});

test('editor の線を持つ相手はコマンドを打て、viewer は見るだけ', async t => {
  const f = await lent(t);
  const opened = (await f.request('/v1/environments', { method: 'POST', data: {} })).json.environment;
  const viewer = await f.request('/v1/principals', { method: 'POST', data: { name: 'viewer', key: true } });
  const editor = await f.request('/v1/principals', { method: 'POST', data: { name: 'editor', key: true } });
  for (const [who, relation] of [[viewer, 'viewer'], [editor, 'editor']])
    assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: who.json.principal.id, relation, object_type: 'resource', object_id: opened.id } })).status, 201);
  const command = { command: node("console.log('shared')") };
  assert.equal((await f.request('/v1/environments/' + opened.id, { anonymous: true, token: viewer.json.token })).status, 200);
  assert.equal((await f.request('/v1/environments/' + opened.id + '/commands', { method: 'POST', anonymous: true, token: viewer.json.token, data: command })).status, 403);
  const ran = await f.request('/v1/environments/' + opened.id + '/commands', { method: 'POST', anonymous: true, token: editor.json.token, data: command });
  assert.equal(ran.status, 200, ran.text); assert.equal(ran.json.command.stdout.trim(), 'shared');
});

test('計算時間は使った分だけ減り、持ち主が決めた上限を超えると開けない', async t => {
  const f = await lent(t, { compute: { monthlySeconds: 3600 } });
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: 'worker', key: true } });
  const worker = made.json.principal.id, token = made.json.token;
  assert.equal((await f.request('/v1/principals/' + worker + '/compute', { method: 'PUT', anonymous: true, token, data: { monthly_seconds: 10 } })).status, 403, 'not its own to set');
  assert.equal((await f.request('/v1/principals/' + worker + '/compute', { method: 'PUT', data: { monthly_seconds: 7200 } })).status, 400, 'never above what Foundation allows');
  const limited = await f.request('/v1/principals/' + worker + '/compute', { method: 'PUT', data: { monthly_seconds: 60 } });
  assert.equal(limited.json.compute.limit_seconds, 60);
  const opened = (await f.request('/v1/environments', { method: 'POST', anonymous: true, token, data: { size: 'medium' } })).json.environment;
  f.app.store.db.prepare('UPDATE environments SET started_at=started_at-40000 WHERE resource_id=?').run(opened.id);
  assert.equal((await f.request('/v1/environments/' + opened.id, { method: 'DELETE', anonymous: true, token, data: {} })).status, 200);
  const used = (await f.request('/v1/principals/' + worker + '/compute')).json.compute;
  assert.equal((await f.request('/v1/principals/' + worker + '/compute', { anonymous: true, token })).status, 200, 'it may see its own use');
  assert.ok(used.used_seconds >= 80, 'a medium machine spends twice its time');
  const refused = await f.request('/v1/environments', { method: 'POST', anonymous: true, token, data: {} });
  assert.equal(refused.status, 429); assert.equal(refused.json.error.code, 'compute_limit');
});

test('放置が続いた環境は止まり、しばらくして消え、リソースの入口から閉じると機械も止まる', async t => {
  const f = await lent(t);
  const idle = (await f.request('/v1/environments', { method: 'POST', data: { lifetime: { idle_seconds: 30 } } })).json.environment;
  f.app.store.db.prepare('UPDATE environments SET last_active_at=last_active_at-31000 WHERE resource_id=?').run(idle.id);
  await f.app.environments.sweep();
  assert.equal((await f.request('/v1/environments/' + idle.id)).json.environment.status, 'stopped');
  await f.app.environments.sweep(Date.now() + 3700_000);
  assert.equal((await f.request('/v1/environments/' + idle.id)).status, 404);
  const other = (await f.request('/v1/environments', { method: 'POST', data: {} })).json.environment;
  const machine = f.app.environments.get(other.id).machine;
  assert.equal((await f.request('/v1/resources/' + other.id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal(f.app.environments.runner.machines.has(machine), false);
});

test('実行基盤がなければ環境は使えないと答える', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const refused = await f.request('/v1/environments', { method: 'POST', token: agent.token, data: {} });
  assert.equal(refused.status, 503); assert.equal(refused.json.error.code, 'environments_unavailable');
});
