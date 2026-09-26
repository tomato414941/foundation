import test from 'node:test';
import assert from 'node:assert/strict';
import { awsRole } from '../src/connectors/aws/index.mjs';
import { FakeAws } from '../src/connectors/aws/fixture.mjs';
import { Connectors } from '../src/connectors.mjs';
import { fixture, USER_A } from './helpers.mjs';

// The link Foundation hands over names the template, the stack, Foundation's own role and the external ID.
function linkParameters(url) {
  const parsed = new URL(url);
  return Object.fromEntries(new URLSearchParams(parsed.hash.slice(parsed.hash.indexOf('?') + 1)));
}
async function connected(t) {
  const aws = new FakeAws();
  const f = await fixture(t, { connectors: [awsRole(aws)] });
  return { aws, f };
}

test('AWSは鍵を預からず、持ち主が作った役割を外部IDつきで引き受け、使うたびに一時的な認証情報を得る', async t => {
  const { aws, f } = await connected(t);
  const catalog = (await f.request('/v1/connectors', { anonymous: true })).json.connectors;
  assert.deepEqual(catalog.map(item => [item.id, item.flow, item.provider]), [['aws.role', 'role', 'aws']]);
  const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'aws.role' } });
  assert.equal(started.status, 200, started.text);
  const parameters = linkParameters(started.json.url);
  assert.match(started.json.url, /^https:\/\/console\.aws\.amazon\.com\/cloudformation\/home\?region=ap-northeast-1#\/stacks\/create\/review\?/);
  assert.match(parameters.templateURL, /^https:\/\/fixture-bucket\.s3\.ap-northeast-1\.amazonaws\.com\/foundation\/aws-connection\.yaml\?X-Amz-Algorithm=/);
  assert.equal(parameters.stackName, 'foundation-connection');
  assert.equal(parameters.param_FoundationRoleArn, 'arn:aws:iam::111111111111:role/foundation-host-InstanceRole');
  assert.match(parameters.param_ExternalId, /^[A-Za-z0-9_-]{32}$/);
  assert.deepEqual(started.json.complete.fields.map(field => field.name), ['role_arn']);
  assert.ok(aws.calls.some(call => call.options.method === 'PUT'), 'the template was placed in the bucket for the link to reach');

  // A wrong paste is answered, and the same flow accepts the right one afterwards.
  const wrong = await f.request('/v1/connections/complete', { method: 'POST', data: { state: started.json.state, fields: { role_arn: 'not an arn' } } });
  assert.equal(wrong.status, 400); assert.equal(wrong.json.error.code, 'invalid_role');
  const other = aws.make('some-other-external-id');
  const refused = await f.request('/v1/connections/complete', { method: 'POST', data: { state: started.json.state, fields: { role_arn: other } } });
  assert.equal(refused.status, 409); assert.equal(refused.json.error.code, 'reconnect_required');
  const arn = aws.make(parameters.param_ExternalId);
  const done = await f.request('/v1/connections/complete', { method: 'POST', data: { state: started.json.state, fields: { role_arn: arn } } });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.json.connection.method, 'delegated'); assert.equal(done.json.connection.provider, 'aws');
  assert.equal(done.json.connection.subject, 'aws:222222222222:foundation-connection-FoundationRole-ABC');
  assert.equal(done.json.connection.label, '222222222222 / foundation-connection-FoundationRole-ABC');
  assert.doesNotMatch(done.text, new RegExp(parameters.param_ExternalId), 'the external ID is Foundation\'s to keep');
  assert.equal((await f.request('/v1/connections/complete', { method: 'POST', data: { state: started.json.state, fields: { role_arn: arn } } })).status, 400, 'the flow is spent');

  // Delivering derives an hour of credentials; nothing kept is a credential.
  const key = await f.issueKey();
  const first = await f.deliver(done.json.connection, { token: key.token });
  assert.equal(first.status, 200, first.text);
  assert.deepEqual(Object.keys(first.json.delivery.environment), ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION']);
  assert.equal(first.json.delivery.environment.AWS_SESSION_TOKEN, 'assumed-session-2');
  assert.ok(first.json.expires_in > 3500 && first.json.expires_in <= 3600);
  const second = await f.deliver(done.json.connection, { token: key.token });
  assert.equal(second.json.delivery.environment.AWS_SESSION_TOKEN, 'assumed-session-3', 'each delivery asks AWS again');
  const state = f.app.grants.state(f.app.grants.held(USER_A, done.json.connection.id));
  assert.deepEqual(Object.keys(state.private_state), ['role_arn', 'external_id']);
  assert.equal((await f.request('/v1/holdings/' + done.json.connection.id + '/content')).status, 405);

  // The role gone at AWS: delivery says so, and the connection asks to be made again.
  aws.roles.delete(arn);
  const gone = await f.deliver(done.json.connection, { token: key.token });
  assert.equal(gone.status, 409); assert.equal(gone.json.error.code, 'reconnect_required');
  assert.equal((await f.request('/v1/connections')).json.connections[0].status, 'reconnect_required');
});

test('役割の流れは持ち主のブラウザーからだけ始まり、他人の流れを完了させることはできない', async t => {
  const { aws, f } = await connected(t), key = await f.issueKey();
  assert.equal((await f.request('/v1/connections', { method: 'POST', token: key.token, anonymous: true, data: { connector: 'aws.role' } })).status, 403);
  const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'aws.role' } });
  const arn = aws.make(linkParameters(started.json.url).param_ExternalId);
  await f.login('second@example.test');
  const foreign = await f.request('/v1/connections/complete', { method: 'POST', data: { state: started.json.state, fields: { role_arn: arn } } });
  assert.equal(foreign.status, 400); assert.equal(foreign.json.error.code, 'invalid_state');
  assert.equal((await f.request('/v1/connections')).json.connections.length, 0);
});

test('接続方法の一覧にAWSが並び、設定がなければ利用できないと示す', () => {
  const registry = new Connectors([awsRole(new FakeAws())]);
  assert.equal(registry.describe('aws.role').available, true);
  assert.equal(registry.describe('aws.role').credential_type, 'sts_temporary_credentials');
  assert.equal(registry.describe('aws.role').can_revoke, false);
});
