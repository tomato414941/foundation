import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { AwsConnections } from '../runtime/aws.js';
import type { AwsConnectionRequest } from '../shared/aws.js';

const source = { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:user/team/operator', UserId: 'AIDOPERATOR' };
const target = { Account: '999999999999', Arn: 'arn:aws:sts::999999999999:assumed-role/Example/first', UserId: 'AROEXAMPLE:first' };
const role = { arn: 'arn:aws:iam::999999999999:role/team/Example', externalId: 'foundation-external-id' };
const expiresAt = () => Date.now() + 3_600_000;
function environment(t: TestContext) {
  for (const [key, value] of Object.entries({ AWS_ACCESS_KEY_ID: 'environment-key', AWS_SECRET_ACCESS_KEY: 'environment-secret',
    AWS_SESSION_TOKEN: 'environment-session', AWS_PROFILE: undefined })) {
    const previous = process.env[key];
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
    t.after(() => { if (previous === undefined) delete process.env[key]; else process.env[key] = previous; });
  }
}
function sts(t: TestContext) {
  const calls: Array<{ kind: string; key: string; secret: string; token?: string; input?: AssumeRoleCommand['input'] }> = [];
  const identities = { source, target };
  t.mock.method(STSClient.prototype, 'send', async function(this: STSClient, command: unknown) {
    const credentials = await this.config.credentials();
    calls.push({ kind: command instanceof AssumeRoleCommand ? 'role' : 'identity', key: credentials.accessKeyId,
      secret: credentials.secretAccessKey, token: credentials.sessionToken,
      ...(command instanceof AssumeRoleCommand ? { input: command.input } : {}) });
    if (command instanceof AssumeRoleCommand) return { Credentials: { AccessKeyId: 'assumed-key',
      SecretAccessKey: 'assumed-secret', SessionToken: 'assumed-session', Expiration: new Date(expiresAt()) } };
    if (command instanceof GetCallerIdentityCommand)
      return credentials.accessKeyId === 'assumed-key' ? identities.target : identities.source;
    throw new Error('Unexpected AWS request.');
  });
  return { calls, identities };
}
const authentications = (): AwsConnectionRequest['authentication'][] => [
  { kind: 'access_key', accessKeyId: 'input-key', secretAccessKey: 'input-secret' },
  { kind: 'session', accessKeyId: 'input-key', secretAccessKey: 'input-secret', sessionToken: 'input-session', expiresAt: expiresAt() },
  { kind: 'environment' },
];

test('アクセスキー・一時認証情報・実行環境の認証でAWSの身元と利用する認証情報を確認する', async t => {
  for (const authentication of authentications()) await t.test(authentication.kind, async t => {
    environment(t); const { calls } = sts(t);
    const result = await new AwsConnections().obtain({ authentication, region: 'us-west-2' });
    const ambient = authentication.kind === 'environment';
    assert.deepEqual(result.credentials, { AWS_ACCESS_KEY_ID: ambient ? 'environment-key' : 'input-key',
      AWS_SECRET_ACCESS_KEY: ambient ? 'environment-secret' : 'input-secret',
      AWS_SESSION_TOKEN: ambient ? 'environment-session' : authentication.kind === 'session' ? 'input-session' : '',
      AWS_DEFAULT_REGION: 'us-west-2', AWS_REGION: 'us-west-2' });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.key, result.credentials.AWS_ACCESS_KEY_ID);
    assert.deepEqual(result.state.sourceIdentity, { accountId: source.Account, arn: source.Arn, principalId: source.UserId });
    assert.deepEqual(result.state.identity, result.state.sourceIdentity);
    assert.deepEqual(result.state.authentication, authentication);
  });
});

test('各認証元から別のIAMロールを引き受け、検証したロールの認証情報を利用する', async t => {
  for (const authentication of authentications()) await t.test(authentication.kind, async t => {
    environment(t); const { calls } = sts(t);
    const result = await new AwsConnections().obtain({ authentication, region: 'ap-northeast-1', role });
    assert.deepEqual(calls.map(call => [call.kind, call.key]), [
      ['identity', authentication.kind === 'environment' ? 'environment-key' : 'input-key'],
      ['role', authentication.kind === 'environment' ? 'environment-key' : 'input-key'], ['identity', 'assumed-key'],
    ]);
    assert.equal(calls[1]!.input!.RoleArn, role.arn);
    assert.equal(calls[1]!.input!.ExternalId, role.externalId);
    assert.equal(calls[1]!.input!.DurationSeconds, 3600);
    assert.deepEqual(result.credentials, { AWS_ACCESS_KEY_ID: 'assumed-key', AWS_SECRET_ACCESS_KEY: 'assumed-secret',
      AWS_SESSION_TOKEN: 'assumed-session', AWS_DEFAULT_REGION: 'ap-northeast-1', AWS_REGION: 'ap-northeast-1' });
    assert.deepEqual(result.state.identity, { accountId: target.Account, arn: target.Arn, principalId: 'AROEXAMPLE' });
  });
});

test('External IDを指定しないロールも選んだ認証元で利用する', async t => {
  const { calls } = sts(t);
  await new AwsConnections().obtain({ authentication: authentications()[0]!, region: 'us-west-2', role: { arn: role.arn } });
  assert.equal(calls[1]!.input!.RoleArn, role.arn);
  assert.equal(calls[1]!.input!.ExternalId, undefined);
});

test('ロールのセッションや実行環境のキーが更新されても同じ身元で接続を利用する', async t => {
  environment(t); const { identities } = sts(t), provider = new AwsConnections();
  identities.source = { Account: source.Account, Arn: 'arn:aws:sts::123456789012:assumed-role/Host/first', UserId: 'AROHOST:first' };
  const first = await provider.obtain({ authentication: { kind: 'environment' }, region: 'us-west-2', role });
  process.env.AWS_ACCESS_KEY_ID = 'rotated-environment-key';
  identities.source = { ...identities.source, Arn: 'arn:aws:sts::123456789012:assumed-role/Host/next', UserId: 'AROHOST:next' };
  identities.target = { ...target, Arn: 'arn:aws:sts::999999999999:assumed-role/Example/next', UserId: 'AROEXAMPLE:next' };
  const updated = await provider.obtain(first.state, first.state);
  assert.equal(updated.state.sourceIdentity.principalId, 'AROHOST');
  assert.equal(updated.state.identity.principalId, 'AROEXAMPLE');
  assert.equal(updated.credentials.AWS_ACCESS_KEY_ID, 'assumed-key');
});

test('認証元またはロールの身元が変わったら再接続での確認を求める', async t => {
  for (const changed of ['source', 'target'] as const) await t.test(changed, async t => {
    const { identities } = sts(t), provider = new AwsConnections();
    const first = await provider.obtain({ authentication: authentications()[0]!, region: 'us-west-2', role });
    identities[changed] = { ...identities[changed], UserId: 'DIFFERENTPRINCIPAL:session' };
    await assert.rejects(provider.obtain(first.state, first.state), { code: 'account_changed' });
  });
});

test('指定したロールと異なるアカウント・パーティション・ロールを再確認する', async t => {
  for (const Arn of ['arn:aws:sts::888888888888:assumed-role/Example/first',
    'arn:aws-cn:sts::999999999999:assumed-role/Example/first', 'arn:aws:sts::999999999999:assumed-role/Other/first'])
    await t.test(Arn, async t => {
      const { identities } = sts(t);
      identities.target = { ...target, Arn, Account: Arn.split(':')[4]! };
      await assert.rejects(new AwsConnections().obtain({ authentication: authentications()[0]!, region: 'us-west-2', role }),
        { code: 'account_changed' });
    });
});

test('期限切れの一時認証情報やAWSの期限切れ応答に対して再接続を求める', async t => {
  await t.test('declared expiry', async () => {
    await assert.rejects(new AwsConnections().obtain({ authentication: { kind: 'session', accessKeyId: 'old-key',
      secretAccessKey: 'old-secret', sessionToken: 'old-session', expiresAt: Date.now() - 1000 }, region: 'us-west-2' }),
      { code: 'reconnect_required' });
  });
  await t.test('AWS expiry', async t => {
    t.mock.method(STSClient.prototype, 'send', async () => { throw Object.assign(new Error('Expired'), { name: 'ExpiredToken' }); });
    await assert.rejects(new AwsConnections().obtain({ authentication: authentications()[1]!, region: 'us-west-2' }),
      { code: 'reconnect_required' });
  });
});

test('入力したAWSキーが拒否されたらその認証元のエラーを返す', async t => {
  environment(t); const keys: string[] = [];
  t.mock.method(STSClient.prototype, 'send', async function(this: STSClient) {
    keys.push((await this.config.credentials()).accessKeyId);
    throw Object.assign(new Error('Rejected'), { name: 'InvalidClientTokenId' });
  });
  await assert.rejects(new AwsConnections().obtain({ authentication: authentications()[0]!, region: 'us-west-2' }),
    { code: 'aws_authentication_failed' });
  assert.deepEqual(keys, ['input-key']);
});

test('ロールの引き受けが拒否されたら信頼ポリシーの確認を求める', async t => {
  t.mock.method(STSClient.prototype, 'send', async (command: unknown) => {
    if (command instanceof AssumeRoleCommand) throw Object.assign(new Error('Denied'), { name: 'AccessDenied' });
    return source;
  });
  await assert.rejects(new AwsConnections().obtain({ authentication: authentications()[0]!, region: 'us-west-2', role }),
    { code: 'role_denied' });
});
