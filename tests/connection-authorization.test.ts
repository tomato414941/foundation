import test from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionMaterial, connectionMetadata } from '../shared/connections.js';

const material = () => ConnectionMaterial.parse({ format: 2, methodId: 'aws:authentication',
  method: { name: 'AWS', kind: 'aws', config: {} },
  generation: 'f109ab1d-bdc6-4eb6-bb2a-3adfc8e831e3', appId: null, appGeneration: null,
  aws: { authentication: { kind: 'session', accessKeyId: 'source-key', secretAccessKey: 'source-secret',
    sessionToken: 'source-session', expiresAt: Date.now() + 3_600_000 }, region: 'us-west-2',
    role: { arn: 'arn:aws:iam::999999999999:role/team/Target', externalId: 'approved-external-id' },
    sourceIdentity: { accountId: '123456789012', principalId: 'AROSOURCE',
      arn: 'arn:aws:sts::123456789012:assumed-role/Source/first-session' },
    identity: { accountId: '999999999999', principalId: 'AROTARGET',
      arn: 'arn:aws:sts::999999999999:assumed-role/Target/first-session' } } });

test('AWSのキーと期限とロールセッションを更新しても承認した身元と接続設定を維持する', async () => {
  const previous = material(), updated = structuredClone(previous);
  updated.aws!.authentication = { kind: 'session', accessKeyId: 'updated-key', secretAccessKey: 'updated-secret',
    sessionToken: 'updated-session', expiresAt: Date.now() + 7_200_000 };
  updated.aws!.sourceIdentity.arn = 'arn:aws:sts::123456789012:assumed-role/Source/next-session';
  updated.aws!.identity.arn = 'arn:aws:sts::999999999999:assumed-role/Target/next-session';
  const approved = await connectionMetadata(previous), renewed = await connectionMetadata(updated);
  assert.equal(renewed.authorizationDigest, approved.authorizationDigest);
  assert.equal(renewed.accountId, approved.accountId);
  assert.equal(renewed.accountId, 'arn:aws:sts::999999999999:assumed-role/Target');
  assert.equal(renewed.aws!.expiresAt, updated.aws!.authentication.expiresAt);
});

test('AWSの認証元とロールとリージョンとExternal IDの変更を新しい承認内容として扱う', async t => {
  const previous = material(), approved = await connectionMetadata(previous);
  const changes: Array<[string, (value: ReturnType<typeof material>) => void]> = [
    ['authentication source', value => { value.aws!.authentication = { kind: 'environment' }; }],
    ['source principal', value => { value.aws!.sourceIdentity.principalId = 'ARONEWSOURCE'; }],
    ['source account', value => { value.aws!.sourceIdentity.accountId = '111111111111';
      value.aws!.sourceIdentity.arn = 'arn:aws:sts::111111111111:assumed-role/Source/session'; }],
    ['target principal', value => { value.aws!.identity.principalId = 'AROREPLACEDTARGET'; }],
    ['role', value => { value.aws!.role!.arn = 'arn:aws:iam::999999999999:role/Other'; }],
    ['external ID', value => { value.aws!.role!.externalId = 'changed-external-id'; }],
    ['region', value => { value.aws!.region = 'ap-northeast-1'; }],
  ];
  for (const [name, change] of changes) await t.test(name, async () => {
    const updated = structuredClone(previous); change(updated);
    assert.notEqual((await connectionMetadata(updated)).authorizationDigest, approved.authorizationDigest);
  });
});
