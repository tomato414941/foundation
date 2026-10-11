import test from 'node:test';
import assert from 'node:assert/strict';
import { STSClient } from '@aws-sdk/client-sts';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import { awsPrincipal, detectAwsPrincipal } from '../runtime/aws-principal.js';

const caller = { Arn: 'arn:aws:sts::123456789012:assumed-role/foundation-host/i-0abc',
  Account: '123456789012', UserId: 'AROFOUNDATIONEXAMPLE:i-0abc' };
const role = { Arn: 'arn:aws:iam::123456789012:role/service/foundation-host', RoleName: 'foundation-host',
  RoleId: 'AROFOUNDATIONEXAMPLE' };

test('IAMのロールとユーザーのARNをパスを保って信頼先として使う', () => {
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:role/service/foundation-host'),
    'arn:aws:iam::123456789012:role/service/foundation-host');
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:user/operator'), 'arn:aws:iam::123456789012:user/operator');
  const longPath = 'arn:aws:iam::123456789012:role/' + 'project/'.repeat(35) + 'foundation-host';
  assert.equal(awsPrincipal(longPath), longPath);
});

test('rootとフェデレーションの身元をIAMロールの信頼先として未確認にする', () => {
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:root'), null);
  assert.equal(awsPrincipal('arn:aws:sts::123456789012:federated-user/guest'), null);
});

test('引き受けたロールをIAMで照合し、パス付きの完全なARNを求める', async t => {
  t.mock.method(STSClient.prototype, 'send', async () => caller);
  t.mock.method(IAMClient.prototype, 'send', async (command: GetRoleCommand) => {
    assert.equal(command.input.RoleName, 'foundation-host');
    return { Role: role };
  });
  assert.equal(await detectAwsPrincipal(), role.Arn);
});

test('IAMで確認した長いパスやAWSパーティションを含むARNを保持する', async t => {
  for (const [partition, path] of [['aws', 'project/'.repeat(35)], ['aws-us-gov', 'team/'], ['aws-cn', 'service/']])
    await t.test(partition!, async t => {
      const arn = `arn:${partition}:iam::123456789012:role/${path}foundation-host`;
      t.mock.method(STSClient.prototype, 'send', async () => ({ ...caller,
        Arn: `arn:${partition}:sts::123456789012:assumed-role/foundation-host/i-0abc` }));
      t.mock.method(IAMClient.prototype, 'send', async () => ({ Role: { ...role, Arn: arn } }));
      assert.equal(await detectAwsPrincipal(), arn);
    });
});

test('呼び出し元と異なるアカウントやロールの情報を未確認にする', async t => {
  for (const [name, returned] of [
    ['account', { ...role, Arn: 'arn:aws:iam::999999999999:role/service/foundation-host' }],
    ['partition', { ...role, Arn: 'arn:aws-cn:iam::123456789012:role/service/foundation-host' }],
    ['role ID', { ...role, RoleId: 'ARODIFFERENTEXAMPLE' }],
    ['role name', { ...role, Arn: 'arn:aws:iam::123456789012:role/service/other-role' }],
    ['user', { ...role, Arn: 'arn:aws:iam::123456789012:user/foundation-host' }],
    ['missing ARN', { ...role, Arn: undefined }],
  ] as const) await t.test(name, async t => {
    t.mock.method(STSClient.prototype, 'send', async () => caller);
    t.mock.method(IAMClient.prototype, 'send', async () => ({ Role: returned }));
    assert.equal(await detectAwsPrincipal(), null);
  });
});

test('IAMユーザーの身元をそのARNで確認する', async t => {
  const arn = 'arn:aws:iam::123456789012:user/team/operator';
  t.mock.method(STSClient.prototype, 'send', async () => ({ Arn: arn, Account: '123456789012', UserId: 'AIDOPERATOR' }));
  assert.equal(await detectAwsPrincipal(), arn);
});

test('認証情報不足やIAM権限不足や通信失敗を未確認として扱う', async t => {
  await t.test('credentials', async t => {
    t.mock.method(STSClient.prototype, 'send', async () => { throw new Error('CredentialsProviderError'); });
    assert.equal(await detectAwsPrincipal(), null);
  });
  for (const error of ['AccessDenied', 'NetworkError']) await t.test(error, async t => {
    t.mock.method(STSClient.prototype, 'send', async () => caller);
    t.mock.method(IAMClient.prototype, 'send', async () => { throw new Error(error); });
    assert.equal(await detectAwsPrincipal(), null);
  });
});

test('判定期限を過ぎたロール情報の取得を中断し未確認として扱う', async t => {
  t.mock.method(STSClient.prototype, 'send', async () => caller);
  t.mock.method(IAMClient.prototype, 'send', (_command: GetRoleCommand, options: { abortSignal: AbortSignal }) =>
    new Promise((_resolve, reject) => {
      options.abortSignal.addEventListener('abort', () => reject(options.abortSignal.reason), { once: true });
      const keepAlive = setTimeout(() => reject(new Error('The request was not aborted.')), 1000);
      options.abortSignal.addEventListener('abort', () => clearTimeout(keepAlive), { once: true });
    }));
  assert.equal(await detectAwsPrincipal(25), null);
});
