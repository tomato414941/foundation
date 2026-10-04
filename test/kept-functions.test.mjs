import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

const post = { description: 'Post a message', parameters: { channel: { required: true }, text: { description: 'What to say', required: true } },
  request: { url: 'https://slack.example.test/api/chat.postMessage', method: 'POST', headers: { authorization: 'Bearer ' }, json: { channel: '', text: '' },
    bindings: [{ target: '/json/channel', parts: [{ parameter: 'channel' }] }, { target: '/json/text', parts: ['[bot] ', { parameter: 'text' }] }] } };
const place = (f, name, data, options = {}) => f.request('/v1/principals/me/resources?kind=function&name=' + encodeURIComponent(name), { method: 'PUT', data, ...options });

test('持ち主はファンクションを名前で置き、一覧し、読み、置き換え、名前を変え、消す', async t => {
  const f = await fixture(t);
  const made = await place(f, 'slack/post', post);
  assert.equal(made.status, 200, made.text);
  assert.equal(made.json.resource.kind, 'function'); assert.equal(made.json.resource.owner_id, USER_A);
  assert.deepEqual(made.json.resource.parameters, post.parameters);
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=function')).json.resources.map(row => row.name), ['slack/post']);
  assert.equal((await f.request('/v1/principals/me/resources?kind=function&name=slack/post')).json.resource.id, made.json.resource.id);
  const again = await place(f, 'slack/post', { ...post, description: 'Post to Slack' });
  assert.equal(again.json.resource.id, made.json.resource.id, 'the same name is the same function');
  assert.equal(again.json.resource.description, 'Post to Slack');
  const renamed = await f.request('/v1/resources/' + made.json.resource.id, { method: 'PATCH', data: { name: 'slack/say' } });
  assert.equal(renamed.json.resource.name, 'slack/say');
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id)).json.resource.request.url, post.request.url);
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id, { method: 'DELETE', data: {} })).status, 200);
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=function')).json.resources, []);
});

test('ファンクションの定義は送るリクエストとして確かめ、持ち主のものを参照し、宣言した引数だけを使う', async t => {
  const f = await fixture(t);
  const refused = async (data, code) => { const response = await place(f, 'x', data); assert.equal(response.status >= 400, true, response.text); assert.equal(response.json.error.code, code, response.text); };
  await refused({ request: { url: 'http://slack.example.test/' } }, 'invalid_url');
  await refused({ request: { url: 'https://slack.example.test/', json: { text: '' }, bindings: [{ target: '/json/text', parts: [{ parameter: 'text' }] }] } }, 'invalid_function');
  await refused({ request: { url: 'https://slack.example.test/', save: 'kept' } }, 'invalid_function');
  await refused({ parameters: { Bad: {} }, request: { url: 'https://slack.example.test/' } }, 'invalid_function');
  await refused({ request: { url: 'https://slack.example.test/', headers: { authorization: '' }, bindings: [{ target: '/headers/authorization', parts: [{ name: 'no-such-secret' }] }] } }, 'not_found');
  const secret = (await f.keep('secret', 'slack-token', 'xoxb-1')).json.resource;
  const made = await place(f, 'slack/post', { ...post, query: { pretty: ['1'], thread: [{ parameter: 'channel' }] },
    request: { ...post.request, bindings: [...post.request.bindings, { target: '/headers/authorization', parts: ['Bearer ', { id: secret.id }] }] } });
  assert.equal(made.status, 200, made.text);
  assert.deepEqual(made.json.resource.query, { pretty: ['1'], thread: [{ parameter: 'channel' }] });
});

test('ファンクションを置けるのは持ち主のものを使える者で、見せられただけの者は読める', async t => {
  const f = await fixture(t), agent = await f.issueKey(), stranger = await f.become('stranger');
  const made = await place(f, 'ping', { request: { url: 'https://api.example.test/ping' } });
  assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=function&name=ping', { method: 'PUT', token: agent.token, data: { request: { url: 'https://api.example.test/pong' } } })).status, 200, 'one who acts for the owner');
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id, { token: stranger.token, anonymous: true })).status, 401);
  const reader = await f.request('/v1/principals', { method: 'POST', data: { name: 'reader', key: true } });
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id, { token: reader.json.token, anonymous: true })).status, 403);
  assert.equal((await f.request('/v1/principals/' + reader.json.principal.id + '/relations', { method: 'POST', data: { relation: 'invoker', object_type: 'resource', object_id: made.json.resource.id } })).status, 201);
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id, { token: reader.json.token, anonymous: true })).json.resource.name, 'ping');
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id, { method: 'PUT', token: reader.json.token, anonymous: true, data: { request: { url: 'https://evil.example.test/' } } })).status, 403, 'calling is not changing what it does');
});
