import test from 'node:test';
import assert from 'node:assert/strict';
import { CommandProcess } from '../runtime/command.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const image = process.env.TEST_COMMAND_IMAGE ??
  'node@sha256:d8e448a56fc63242f70026718378bd4b00f8c82e78d20eefb199224a4d8e33d8';
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
