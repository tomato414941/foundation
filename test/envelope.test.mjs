import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, publicKeyOf, newContentKey, sealContent, openContent, seal, open, wrap, unwrap } from '../cli/envelope.mjs';

test('秘密の鍵で封じた中身を、封筒を受け取った相手だけが開く', () => {
  const alice = generateKey(), bob = generateKey(), carol = generateKey();
  const contentKey = newContentKey(), sealed = sealContent(contentKey, Buffer.from('private bytes'));
  assert.notEqual(sealed.toString(), 'private bytes');
  assert.equal(openContent(contentKey, sealed).toString(), 'private bytes');
  const forBob = seal(contentKey, bob.publicKey);
  assert.deepEqual(open(forBob, bob.privateKey), contentKey);
  assert.throws(() => open(forBob, alice.privateKey));
  assert.throws(() => open(forBob, carol.privateKey));
  assert.deepEqual(publicKeyOf(bob.privateKey), bob.publicKey);
});

test('同じ鍵で作った封筒でも毎回違い、どちらも開く', () => {
  const bob = generateKey(), contentKey = newContentKey();
  const first = seal(contentKey, bob.publicKey), second = seal(contentKey, bob.publicKey);
  assert.notDeepEqual(first, second);
  assert.deepEqual(open(first, bob.privateKey), contentKey);
  assert.deepEqual(open(second, bob.privateKey), contentKey);
});

test('クレデンシャルが出す値で秘密鍵を包み、同じ値でだけほどく', () => {
  const alice = generateKey(), yielded = Buffer.alloc(32, 1);
  const wrapped = wrap(alice.privateKey, yielded);
  assert.deepEqual(unwrap(wrapped, yielded), alice.privateKey);
  assert.throws(() => unwrap(wrapped, Buffer.alloc(32, 2)));
  assert.throws(() => open(Buffer.alloc(10), alice.privateKey), /too short/);
});
