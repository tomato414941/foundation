import test from 'node:test';
import assert from 'node:assert/strict';
import { acceptValues, defineSchema } from '../src/schema.mjs';

const apple = defineSchema([
  { id: 'key_id', label: 'Key ID', pattern: '[A-Za-z0-9]{10}', max: 10 },
  { id: 'team_type', label: 'チーム種別', kind: 'choice', options: [{ value: 'INDIVIDUAL', label: '個人' }, { value: 'IN_HOUSE', label: '社内配布' }] },
  { id: 'key', label: 'APIキー', kind: 'multiline', secret: true },
]);
const code = response => { try { response(); } catch (error) { return error.code; } };

test('A schema lists its fields with a kind, a ceiling and secrecy, and freezes them', () => {
  assert.deepEqual(apple.map(field => [field.id, field.kind, field.secret, field.max]), [['key_id', 'line', false, 10], ['team_type', 'choice', false, 64], ['key', 'multiline', true, 8192]]);
  assert.ok(Object.isFrozen(apple) && Object.isFrozen(apple[0]) && Object.isFrozen(apple[1].options[0]));
});

test('A malformed declaration throws: duplicate ids, missing labels, unknown kinds, options outside a choice', () => {
  for (const fields of [[], [{ id: 'a', label: 'A' }, { id: 'a', label: 'B' }], [{ id: 'a', label: '' }], [{ id: 'a', label: 'A', kind: 'file' }], [{ id: 'a', label: 'A', options: [{ value: 'x', label: 'X' }] }], [{ id: 'a', label: 'A', kind: 'choice' }], [{ id: '1a', label: 'A' }]]) {
    assert.throws(() => defineSchema(fields), JSON.stringify(fields));
  }
});

test('Accepting values takes exactly the declared fields, trimmed, and nothing else', () => {
  const values = acceptValues(apple, { key_id: ' ABC1234567 ', team_type: 'INDIVIDUAL', key: '-----BEGIN\r\nabc\r\n-----END\r\n', extra: 'ignored' });
  assert.deepEqual(values, { key_id: 'ABC1234567', team_type: 'INDIVIDUAL', key: '-----BEGIN\nabc\n-----END' });
});

test('Accepting values rejects a missing value, a wrong shape, spaces in one line, an unknown choice and an overlong value', () => {
  const good = { key_id: 'ABC1234567', team_type: 'INDIVIDUAL', key: 'k' };
  for (const bad of [{ ...good, key: '' }, { ...good, key_id: 'short' }, { ...good, key_id: 'ABC 234567' }, { ...good, team_type: 'COMPANY' }, { ...good, key: 'x'.repeat(8193) }, null, ['x']]) {
    assert.equal(code(() => acceptValues(apple, bad)), 'invalid_values', JSON.stringify(bad));
  }
});
