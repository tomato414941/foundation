import test from 'node:test';
import assert from 'node:assert/strict';
import { processInputs } from '../runtime/inputs.js';
import { encode } from '../shared/encryption.js';

const source = { id: crypto.randomUUID(), output: 'KEY' };

test('形式を指定しない入力は、方式がファイルで渡す出力をファイルにする', async () => {
  const values = await processInputs([{ name: 'KEY', source }], async () => ({ value: encode('{"a":1}'), file: true }));
  assert.deepEqual(values.environment, {});
  assert.equal(Buffer.from(values.files.KEY!, 'base64').toString(), '{"a":1}');
});

test('形式を指定しない入力は、ほかの出力を環境変数の値にする', async () => {
  const values = await processInputs([{ name: 'KEY', source }], async () => ({ value: encode('token') }));
  assert.deepEqual(values.environment, { KEY: 'token' });
  assert.deepEqual(values.files, {});
});

test('入力が指定した形式は、方式の渡し方より優先する', async () => {
  const resolve = async () => ({ value: encode('{"a":"b"}'), file: true });
  assert.deepEqual((await processInputs([{ name: 'KEY', source, format: 'text' }], resolve)).environment, { KEY: '{"a":"b"}' });
  assert.deepEqual((await processInputs([{ name: 'KEY', source, format: 'json', pointer: '/a' }], resolve)).environment, { KEY: 'b' });
});
