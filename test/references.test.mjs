import test from 'node:test';
import assert from 'node:assert/strict';
import { pointerTokens, valueAt, replaceAt } from '../src/json-pointer.mjs';
import { uriTemplate, templateVariables } from '../src/uri-template.mjs';

test('JSON Pointerで空のキー・配列・記号を含むキーをRFC 6901どおりに選択する', () => {
  const value = JSON.parse('{"foo":["bar","baz"],"":0,"a/b":1,"c%d":2,"m~n":8,"a.b":9,"~1":10,"__proto__":{"name":"own"}}');
  for (const [pointer, expected] of [['', value], ['/foo/0', 'bar'], ['/', 0], ['/a~1b', 1], ['/c%d', 2], ['/m~0n', 8], ['/a.b', 9], ['/~01', 10], ['/__proto__/name', 'own']]) {
    assert.deepEqual(valueAt(value, pointer), expected, pointer);
  }
  for (const pointer of ['/foo/01', '/foo/-', '/foo/length', '/foo/2', '/missing', '/constructor', '/a.b/child']) assert.equal(valueAt(value, pointer), undefined, pointer);
  replaceAt(value, '/a~1b', 'next');
  assert.equal(value['a/b'], 'next');
  replaceAt(value, '/__proto__/name', 'changed');
  assert.equal(valueAt(value, '/__proto__/name'), 'changed');
  assert.equal(Object.prototype.name, undefined);
  for (const pointer of ['abc', '#/foo', '/bad~', '/bad~2']) assert.throws(() => pointerTokens(pointer), TypeError);
  assert.throws(() => replaceAt(value, '/missing/child', 'x'), TypeError);
});

test('URI TemplateをRFC 6570に従って展開し、予約文字・Unicode・既存のパーセント表記を保持する', () => {
  const values = { var: 'value', hello: 'Hello World!', path: '/foo/bar', list: ['red', 'green', 'blue'], keys: { semi: ';', dot: '.', comma: ',' },
    url: 'https://example.test/a%2Fb?q=%e3%81%82', unicode: '😀あ', 'a%20b': 'space' };
  for (const [template, expected] of [
    ['{hello}', 'Hello%20World%21'], ['{+path}/here', '/foo/bar/here'], ['{?list*}', '?list=red&list=green&list=blue'],
    ['{?keys*}', '?semi=%3B&dot=.&comma=%2C'], ['{+url}', values.url], ['{unicode:1}', '%F0%9F%98%80'], ['{?a%20b}', '?a%20b=space'],
  ]) assert.equal(uriTemplate(template).expand(values), expected, template);
  assert.deepEqual(templateVariables(uriTemplate('https://{domain}/{+path}{?q,list*}')), ['domain', 'path', 'q', 'list']);
  for (const template of ['{unclosed', '{}', '{x:0}', '{x,,y}', 'bad}']) assert.throws(() => uriTemplate(template));
});
