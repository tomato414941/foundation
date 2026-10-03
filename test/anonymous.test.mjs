import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

const actor = { authorization_details: [{ type: 'relation', relation: 'agent' }] };

test('誰にも承認されていない principal は、相手を指定した依頼を出せず、相手を指定しない依頼だけを出せる', async t => {
  const f = await fixture(t), stranger = await f.become('stranger');
  const named = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: stranger.token, data: { ...actor, to: USER_A } });
  assert.equal(named.status, 403); assert.equal(named.json.error.code, 'unknown_requester');
  assert.deepEqual((await f.request('/v1/requests?to=me&status=pending')).json.requests, [], 'nothing reaches the person it named');
  const open = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: stranger.token, data: actor });
  assert.equal(open.status, 201, open.text);
});

test('承認された相手は、ほかの人を指定して依頼を出せる', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  await f.signin('other@example.test');
  const other = (await f.request('/v1/principals/me')).json.principal.id;
  const named = await f.request('/v1/requests', { method: 'POST', anonymous: true, token: agent.token, data: { ...actor, to: other } });
  assert.equal(named.status, 201, named.text);
});

test('ほかの人の依頼が溜まっても、承認された相手の依頼は受け付けられる', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const insert = f.app.store.db.prepare("INSERT INTO requests (id,from_id,to_id,type,detail,binding_message,steps,status,created_at,expires_at) VALUES (?,?,NULL,'relation','{}','','[]','pending',?,?)");
  f.app.store.transaction(() => { for (let at = 0; at < 1200; at++) insert.run('filler' + String(at).padStart(37, '0'), 'someone-' + at, Date.now(), Date.now() + 3600_000); });
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: 'secret', fields: [{ name: 'npm-token', label: 'npm のトークン' }] }] } });
  assert.equal(asked.status, 201, asked.text);
});

