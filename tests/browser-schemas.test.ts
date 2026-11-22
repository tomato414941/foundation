import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

// Why: the pages run under a content security policy that allows no eval, and zod tries eval when a schema is made
// before it is told not to; the browser reports each try as a violation. Intent: load the shared schemas as a page
// does, first in a fresh process, and count the calls of Function zod makes to try eval.
test('ブラウザでスキーマを読み込んでも、zod に eval を試させない', async () => {
  for (const module of ['shared/contracts.ts', 'shared/aws.ts']) {
    const { stdout } = await promisify(execFile)(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
      globalThis.window = {};
      let calls = 0;
      const original = globalThis.Function;
      globalThis.Function = new Proxy(original, { apply(target, self, args) { calls++; return Reflect.apply(target, self, args); },
        construct(target, args) { calls++; return Reflect.construct(target, args); } });
      await import(${JSON.stringify('file://' + resolve(module))});
      process.stdout.write(String(calls));`]);
    assert.equal(stdout, '0', module);
  }
});
