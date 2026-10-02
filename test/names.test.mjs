import test from 'node:test';
import assert from 'node:assert/strict';
import { principalName, STARS, ROLES } from '../src/names.mjs';

test('始めたばかりの相手に、IAUの星名表と職名から名前を引く', () => {
  assert.ok(STARS.length > 400 && STARS.includes('Vega') && STARS.includes('Achernar'), 'the IAU catalog, by ASCII name');
  assert.ok(STARS.every(star => /^[A-Za-z' ]+$/.test(star)), STARS.filter(star => !/^[A-Za-z' ]+$/.test(star)).join(','));
  const seen = new Set();
  for (let at = 0; at < 200; at++) {
    const name = principalName(), role = ROLES.find(one => name.startsWith(one + ' ') && STARS.includes(name.slice(one.length + 1)));
    assert.ok(role, name);
    seen.add(name);
  }
  assert.ok(seen.size > 100, 'drawn at random');
  assert.ok(new Set(STARS).size === STARS.length && new Set(ROLES).size === ROLES.length, 'no duplicates in the sets');
});
