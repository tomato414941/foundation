import test from 'node:test';
import assert from 'node:assert/strict';
import { CommandProcess } from '../runtime/command.js';

const image = process.env.TEST_COMMAND_IMAGE;
test('指定したコンテナで入力を読み、読み取り専用のファイルシステムと最小の環境を使う', { skip: !image }, async () => {
  const commands = new CommandProcess({ isolation: 'container', image });
  const program = "const fs=require('fs');let writable=true;try{fs.writeFileSync('/write-check','x')}catch{writable=false}" +
    ";process.stdout.write(JSON.stringify({token:process.env.VALUE,file:fs.readFileSync(process.env.INPUT,'utf8'),writable,uid:process.getuid(),auth:process.env.FOUNDATION_TOKEN??null}))";
  const result = await commands.execute({ command: ['node', '-e', program], timeoutSeconds: 20,
    environment: { VALUE: 'selected-value' }, files: { INPUT: Buffer.from('selected-file').toString('base64') } }, new AbortController().signal);
  assert.equal(result.exitCode, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { token: 'selected-value', file: 'selected-file', writable: false,
    uid: process.getuid!(), auth: null });
});

test('コンテナ内の長時間コマンドを制限時間で停止して結果を返す', { skip: !image }, async () => {
  const result = await new CommandProcess({ isolation: 'container', image }).execute({
    command: ['node', '-e', 'setInterval(()=>{},1000)'], timeoutSeconds: 1, environment: {}, files: {},
  }, new AbortController().signal);
  assert.equal(result.timedOut, true);
});
