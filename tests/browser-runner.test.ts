import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

async function runner(t: TestContext, overrides: Record<string, string> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-browser-runner-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const state = join(directory, 'calls');
  await writeFile(join(directory, 'docker'), `#!/usr/bin/env node
import { appendFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2), state = process.env.FOUNDATION_RUNNER_TEST_STATE;
appendFileSync(state, JSON.stringify({ args, environment: Object.fromEntries(['CI', 'TEST_DATABASE_URL', 'FOUNDATION_BROWSER_SHARD', 'FOUNDATION_TEST_PORT', 'FOUNDATION_UI_SERVER'].map(name => [name, process.env[name]])) }) + '\\n');
if (args[0] === 'build') {
  if (process.env.FOUNDATION_RUNNER_TEST_BUILD_EXIT) process.exit(Number(process.env.FOUNDATION_RUNNER_TEST_BUILD_EXIT));
} else if (args[0] === 'run') {
  if (process.env.FOUNDATION_RUNNER_TEST_WAIT) {
    writeFileSync(state + '.ready', 'ready');
    setInterval(() => {}, 1000);
  } else process.exitCode = Number(process.env.FOUNDATION_RUNNER_TEST_EXIT ?? 0);
}
`, { mode: 0o700 });
  function start(arguments_: string[] = []) {
    const child = spawn(process.execPath, [resolve('scripts/browser-tests.mjs'), ...arguments_], {
      env: { ...process.env, PATH: directory + delimiter + process.env.PATH, FOUNDATION_RUNNER_TEST_STATE: state, ...overrides },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
    let stdout = '', stderr = '';
    child.stdout.on('data', value => { stdout += value; });
    child.stderr.on('data', value => { stderr += value; });
    const finished = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveResult, reject) => {
      child.once('error', reject);
      child.once('close', code => resolveResult({ code, stdout, stderr }));
    });
    return { child, finished };
  }
  async function calls() {
    return (await readFile(state, 'utf8')).trim().split('\n').map(line => JSON.parse(line) as { args: string[]; environment: Record<string, string> });
  }
  async function ready() {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await readFile(state + '.ready', 'utf8').catch(() => '') === 'ready') return;
      await delay(20);
    }
    throw new Error('The test container did not start.');
  }
  return { start, calls, ready };
}

test('ブラウザコンテナへ接続設定と分割指定と選んだテストを渡す', async t => {
  const environment = { CI: 'true', TEST_DATABASE_URL: 'postgres://browser-test:fixture-only@127.0.0.1:5432/browser_test',
    FOUNDATION_BROWSER_SHARD: '2/2', FOUNDATION_TEST_PORT: '3489', FOUNDATION_UI_SERVER: 'true' };
  const fixture = await runner(t, environment);
  const result = await fixture.start(['BrowserTests.test_例', '-v']).finished;
  assert.equal(result.code, 0, result.stderr);
  const calls = await fixture.calls(), run = calls.find(call => call.args[0] === 'run')!;
  const build = calls.find(call => call.args[0] === 'build')!;
  const image = build.args[build.args.indexOf('--tag') + 1];
  assert.deepEqual(run.environment, environment);
  for (const name of Object.keys(environment)) assert.ok(run.args.some((value, index) => value === '--env' && run.args[index + 1] === name));
  assert.deepEqual(run.args.slice(-5), [image, 'python3', 'tests/browser.py', 'BrowserTests.test_例', '-v']);
  assert.ok(run.args.includes('--rm') && run.args.includes('--init'));
  assert.deepEqual(calls.find(call => call.args[0] === 'rm')?.args, ['rm', '--force', run.args[run.args.indexOf('--name') + 1]]);
  assert.deepEqual(calls.at(-1)?.args, ['image', 'rm', image]);
  assert.ok(!result.stdout.includes(environment.TEST_DATABASE_URL) && !result.stderr.includes(environment.TEST_DATABASE_URL));
});

test('ブラウザテストが失敗すると終了コードを返して自分のコンテナを回収する', async t => {
  const fixture = await runner(t, { FOUNDATION_RUNNER_TEST_EXIT: '43' });
  const result = await fixture.start().finished;
  assert.equal(result.code, 43, result.stderr);
  const calls = await fixture.calls(), run = calls.find(call => call.args[0] === 'run')!;
  assert.deepEqual(calls.find(call => call.args[0] === 'rm')?.args, ['rm', '--force', run.args[run.args.indexOf('--name') + 1]]);
});

test('ブラウザテストの中断で自分のコンテナを回収して中断を返す', async t => {
  const fixture = await runner(t, { FOUNDATION_RUNNER_TEST_WAIT: 'true' });
  const running = fixture.start();
  await fixture.ready();
  running.child.kill('SIGTERM');
  const result = await running.finished;
  assert.equal(result.code, 143, result.stderr);
  const calls = await fixture.calls(), run = calls.find(call => call.args[0] === 'run')!;
  assert.deepEqual(calls.find(call => call.args[0] === 'rm')?.args, ['rm', '--force', run.args[run.args.indexOf('--name') + 1]]);
});

test('ブラウザイメージをビルドできないとビルドの失敗を返す', async t => {
  const fixture = await runner(t, { FOUNDATION_RUNNER_TEST_BUILD_EXIT: '19' });
  const result = await fixture.start().finished;
  assert.equal(result.code, 19, result.stderr);
});
