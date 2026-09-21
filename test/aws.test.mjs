import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signedRequest } from '../src/providers/aws.mjs';
import { awsFixture, AWS_SECRET, AWS_FIELDS } from './aws-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token, data = {}) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data });
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => out += part); child.stderr.on('data', part => err += part);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});

test('Signature Version 4 matches the AWS documentation example', () => {
  // https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html style check: deterministic output for fixed inputs.
  const a = signedRequest({ accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', region: 'us-east-1', params: { Action: 'GetCallerIdentity', Version: '2011-06-15' }, now: new Date('2015-08-30T12:36:00Z') });
  const b = signedRequest({ accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', region: 'us-east-1', params: { Action: 'GetCallerIdentity', Version: '2011-06-15' }, now: new Date('2015-08-30T12:36:00Z') });
  assert.equal(a.headers.authorization, b.headers.authorization);
  assert.match(a.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-1\/sts\/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/);
  assert.equal(a.headers['x-amz-date'], '20150830T123600Z');
  assert.notEqual(signedRequest({ accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'other', region: 'us-east-1', params: { Action: 'GetCallerIdentity' }, now: new Date('2015-08-30T12:36:00Z') }).headers.authorization, a.headers.authorization);
});

test('AWS import verifies the key with GetCallerIdentity, proves the role once, and stores only the long-lived key encrypted', async t => {
  const f = await awsFixture(t), account = await f.awsAccount();
  const state = await f.request('/api/state'), provider = state.json.providers.find(item => item.id === 'aws');
  assert.deepEqual(provider.token_setup.fields.map(field => field.id), ['access_key_id', 'role_arn', 'region']);
  assert.equal(account.label, '123456789012 / foundation-agent');
  assert.deepEqual(account.aws, { account_id: '123456789012', role_arn: AWS_FIELDS.role_arn, region: 'ap-northeast-1', user_arn: 'arn:aws:iam::123456789012:user/foundation' });
  assert.deepEqual(f.aws.calls.map(call => call.params.Action), ['GetCallerIdentity', 'AssumeRole']);
  assert.equal(f.aws.calls[1].params.DurationSeconds, undefined, 'registration probe leaves the duration to AWS');
  assert.ok(!state.text.includes(AWS_SECRET));
  const stored = f.app.store.secrets(f.app.store.account(USER_A, account.id));
  assert.equal(stored.access_token, AWS_SECRET);
  assert.equal(stored.details.session_token, undefined);
});

test('AWS refuses bad identifiers, wrong secrets, untrusted roles and mismatched accounts before storing anything', async t => {
  const f = await awsFixture(t);
  const rejects = (fields, message) => assert.throws(() => f.aws.fields(fields), error => error.status === 400 && message.test(error.message));
  rejects({ ...AWS_FIELDS, access_key_id: 'ASIAIOSFODNN7EXAMPLE' }, /一時認証情報/);
  rejects({ ...AWS_FIELDS, role_arn: 'arn:aws:iam::123:user/x' }, /ロールARN/);
  rejects({ ...AWS_FIELDS, region: 'tokyo' }, /リージョン/);
  rejects(null, /入力/);
  assert.equal((await f.importAws({ token: 'too-short' })).json.error.code, 'invalid_credential');
  const wrong = await f.importAws({ token: 'x'.repeat(40) });
  assert.equal(wrong.status, 409); assert.equal(wrong.json.error.code, 'reconnect_required');
  f.aws.trusted = false;
  const untrusted = await f.importAws();
  assert.equal(untrusted.status, 409); assert.equal(untrusted.json.error.code, 'role_denied');
  f.aws.trusted = true;
  const mismatch = await f.importAws({ fields: { ...AWS_FIELDS, role_arn: 'arn:aws:iam::999999999999:role/other' } });
  assert.equal(mismatch.json.error.code, 'role_denied');
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  assert.equal((await f.importAws()).status, 200);
  assert.equal((await f.importAws()).status, 409, 'same key and role twice');
});

test('Each issuance assumes the role afresh: temporary credentials only, duration passed through untouched, AWS decides the limit', async t => {
  const f = await awsFixture(t), account = await f.awsAccount(), runtime = await f.agent([account.id]);
  const first = await credential(f, account.id, runtime.token);
  assert.equal(first.status, 200, first.text);
  assert.equal(first.json.credential_type, 'aws_temporary');
  assert.equal(first.json.token_env, 'AWS_SECRET_ACCESS_KEY');
  assert.match(first.json.access_token, /^temporary\/secret\/foundation-/);
  assert.equal(first.json.environment.AWS_ACCESS_KEY_ID, 'ASIAEXAMPLE123456789');
  assert.equal(first.json.environment.AWS_SESSION_TOKEN, 'session-token-3600');
  assert.equal(first.json.environment.AWS_REGION, 'ap-northeast-1');
  assert.ok(first.json.expires_at > Date.now() + 3500_000 && first.json.expires_at < Date.now() + 3700_000);
  assert.ok(!first.text.includes(AWS_SECRET), 'the long-lived secret is never issued');
  assert.equal(f.aws.calls.filter(call => call.params.Action === 'AssumeRole').at(-1).params.DurationSeconds, undefined);
  const longer = await credential(f, account.id, runtime.token, { duration: 1800 });
  assert.equal(longer.json.environment.AWS_SESSION_TOKEN, 'session-token-1800');
  assert.equal(f.aws.calls.at(-1).params.DurationSeconds, '1800');
  const tooLong = await credential(f, account.id, runtime.token, { duration: 7200 });
  assert.equal(tooLong.status, 409); assert.equal(tooLong.json.error.code, 'aws_validationerror');
  assert.ok(!tooLong.text.includes('MaxSessionDuration'), 'AWS message text is not relayed verbatim');
  assert.equal((await credential(f, account.id, runtime.token, { duration: 'soon' })).status, 400);
  assert.equal((await credential(f, account.id, runtime.token, { duration: 0 })).status, 400);
  // Stored key stays unchanged and is not overwritten by session material.
  const stored = f.app.store.secrets(f.app.store.account(USER_A, account.id));
  assert.equal(stored.access_token, AWS_SECRET); assert.equal(stored.details.session_token, undefined);
  // A key AWS stops accepting marks the connection for reconnection.
  f.aws.handler = () => json({ Error: { Code: 'InvalidClientTokenId' } }, 403);
  assert.equal((await credential(f, account.id, runtime.token)).json.error.code, 'reconnect_required');
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'reconnect_required');
});

test('The CLI passes --duration through and the child sees only temporary AWS credentials', async t => {
  const f = await awsFixture(t), account = await f.awsAccount(), runtime = await f.agent([account.id]);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-aws-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const probe = ['-e', 'const e=process.env; if(!e.AWS_ACCESS_KEY_ID?.startsWith("ASIA")||!e.AWS_SECRET_ACCESS_KEY?.startsWith("temporary/")||!e.AWS_SESSION_TOKEN||e.AWS_REGION!=="ap-northeast-1"||e.FOUNDATION_ACCESS_TOKEN!==e.AWS_SECRET_ACCESS_KEY)process.exit(2); console.log(e.AWS_SESSION_TOKEN)'];
  const run = await execute(['exec', account.id, '--', process.execPath, ...probe], env);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'session-token-3600');
  const custom = await execute(['exec', '--duration', '900', account.id, '--', process.execPath, ...probe], env);
  assert.equal(custom.code, 0, custom.err); assert.equal(custom.out.trim(), 'session-token-900');
  const refused = await execute(['exec', '--duration', '7200', account.id, '--', process.execPath, '-e', 'console.log("must-not-run")'], env);
  assert.equal(refused.code, 1); assert.match(refused.err, /aws_validationerror/); assert.doesNotMatch(refused.out, /must-not-run/);
  assert.equal((await execute(['exec', '--duration', 'x', account.id, '--', process.execPath, '-e', '1'], env)).code, 1);
  assert.ok(!(run.out + run.err + custom.out + custom.err + refused.err).includes(AWS_SECRET));
});

test('Foundation hands out the CloudFormation stack that creates the user, role and key; a one-tap link appears only with an S3 template URL', async t => {
  const { cloudFormationTemplate, quickCreateUrl, AWS_TEMPLATE_PATH } = await import('../src/providers/aws.mjs');
  const template = cloudFormationTemplate();
  for (const needle of ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::AccessKey', 'sts:AssumeRole', '!GetAtt FoundationUser.Arn', 'SecretAccessKey:', 'RoleArn:', 'MaxSessionDuration: 3600', 'AllowedValues:']) assert.ok(template.includes(needle), needle);
  assert.ok(!/RoleName|UserName: [a-z]/.test(template), 'unnamed resources need only CAPABILITY_IAM');
  const f = await awsFixture(t);
  const served = await f.request(AWS_TEMPLATE_PATH, { anonymous: true });
  assert.equal(served.status, 200); assert.equal(served.text, template); assert.match(served.headers.get('content-disposition'), /foundation-agent\.yaml/);
  const plain = (await f.request('/api/state')).json.providers.find(item => item.id === 'aws').token_setup;
  assert.equal(plain.url, AWS_TEMPLATE_PATH); assert.equal(plain.link_label, '定義ファイルをダウンロード');
  const url = quickCreateUrl('https://foundation-templates.s3.ap-northeast-1.amazonaws.com/foundation-agent.yaml', 'ap-northeast-1');
  assert.match(url, /^https:\/\/ap-northeast-1\.console\.aws\.amazon\.com\/cloudformation\/home\?region=ap-northeast-1#\/stacks\/quickcreate\?templateURL=https%3A%2F%2Ffoundation-templates/);
  assert.equal(quickCreateUrl('', 'ap-northeast-1'), null);
  assert.throws(() => quickCreateUrl('https://evil.example/x.yaml', 'ap-northeast-1'), /S3/);
  const { awsConnection } = await import('../src/providers/catalog.mjs');
  const { FakeAws } = await import('./aws-helper.mjs');
  const oneTap = awsConnection(new FakeAws(), { templateUrl: 'https://foundation-templates.s3.ap-northeast-1.amazonaws.com/foundation-agent.yaml', region: 'ap-northeast-1' }).tokenSetup;
  assert.equal(oneTap.link_label, 'AWS で作成する'); assert.match(oneTap.url, /quickcreate/);
});
