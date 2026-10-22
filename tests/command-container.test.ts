import test from 'node:test';
import assert from 'node:assert/strict';
import { CommandProcess } from '../runtime/command.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const image = process.env.TEST_COMMAND_IMAGE ??
  'node@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205';
test('指定したコンテナで入力を読み、読み取り専用のファイルシステムと最小の環境を使う', async () => {
  const commands = new CommandProcess({ isolation: 'container', image });
  const program = "const fs=require('fs');let writeError=null;try{fs.writeFileSync('/write-check','x')}catch(error){writeError=error.code}" +
    ";process.stdout.write(JSON.stringify({token:process.env.VALUE,file:fs.readFileSync(process.env.INPUT,'utf8'),writeError,uid:process.getuid(),auth:process.env.FOUNDATION_TOKEN??null}))";
  const result = await commands.execute({ command: ['node', '-e', program], timeoutSeconds: 20,
    environment: { VALUE: 'selected-value' }, files: { INPUT: Buffer.from('selected-file').toString('base64') } }, new AbortController().signal);
  assert.equal(result.exitCode, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { token: 'selected-value', file: 'selected-file', writeError: 'EROFS',
    uid: process.getuid!(), auth: null });
});

test('コンテナ内の長時間コマンドを制限時間で停止して結果を返す', async () => {
  const result = await new CommandProcess({ isolation: 'container', image }).execute({
    command: ['node', '-e', 'process.stdout.write("started\\n");setInterval(()=>{},1000)'], timeoutSeconds: 3, environment: {}, files: {},
  }, new AbortController().signal);
  assert.equal(result.stdout, 'started\n', result.stderr);
  assert.equal(result.timedOut, true);
});

test('コンテナの作業領域に保存したファイルを次の実行で読み、複数行の環境変数を渡す', async t => {
  const workspace = await mkdtemp(join(tmpdir(), 'foundation-process-workspace-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const commands = new CommandProcess({ isolation: 'container', image, workspace });
  const writer = await commands.execute({ command: ['node', '-e', 'require("fs").writeFileSync("saved",process.env.VALUE)'],
    workingDirectory: '/workspace', timeoutSeconds: 20, environment: { VALUE: 'first\nsecond' }, files: {},
  }, new AbortController().signal);
  assert.equal(writer.exitCode, 0, writer.stderr);
  const reader = await commands.execute({ command: ['node', '-e', 'process.stdout.write(require("fs").readFileSync("saved"))'],
    workingDirectory: '/workspace', timeoutSeconds: 20, environment: {}, files: {},
  }, new AbortController().signal);
  assert.equal(reader.exitCode, 0, reader.stderr);
  assert.equal(reader.stdout, 'first\nsecond');
});

test('関数の呼び出しごとに作業領域を用意し、実行環境の保存済みファイルを保つ', async t => {
  const workspace = await mkdtemp(join(tmpdir(), 'foundation-function-workspace-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const commands = new CommandProcess({ isolation: 'container', image, workspace });
  const run = (code: string, temporary: boolean) => commands.execute({ command: ['node', '-e', code],
    timeoutSeconds: 20, environment: {}, files: {}, workspace: temporary ? 'temporary' : 'shared',
    ...(temporary ? {} : { workingDirectory: '/workspace' }) }, new AbortController().signal);
  const stored = await run('require("fs").writeFileSync("counter","99")', false);
  assert.equal(stored.exitCode, 0, stored.stderr);
  for (let invocation = 0; invocation < 2; invocation++) {
    const result = await run('const fs=require("fs");const count=(fs.existsSync("counter")?Number(fs.readFileSync("counter")):0)+1;fs.writeFileSync("counter",String(count));console.log(JSON.stringify({count,cwd:process.cwd(),home:process.env.HOME}));', true);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { count: 1, cwd: '/tmp', home: '/tmp' });
  }
  const retained = await run('process.stdout.write(require("fs").readFileSync("counter"))', false);
  assert.equal(retained.exitCode, 0, retained.stderr);
  assert.equal(retained.stdout, '99');
});
