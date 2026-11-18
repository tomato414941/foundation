import test from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionMaterial, connectionMetadata } from '../shared/connections.js';

const material = () => ConnectionMaterial.parse({ format: 3, methodId: 'aws:authentication',
  method: { name: 'AWS', kind: 'aws', config: {} },
  generation: 'f109ab1d-bdc6-4eb6-bb2a-3adfc8e831e3', appId: null, appGeneration: null,
  aws: { authentication: { kind: 'session', accessKeyId: 'source-key', secretAccessKey: 'source-secret',
    sessionToken: 'source-session', expiresAt: Date.now() + 3_600_000 }, region: 'us-west-2',
    role: { arn: 'arn:aws:iam::999999999999:role/team/Target', externalId: 'approved-external-id' },
    sourceIdentity: { accountId: '123456789012', principalId: 'AROSOURCE',
      arn: 'arn:aws:sts::123456789012:assumed-role/Source/first-session' },
    identity: { accountId: '999999999999', principalId: 'AROTARGET',
      arn: 'arn:aws:sts::999999999999:assumed-role/Target/first-session' } } });

test('AWSのキーとロールセッションを更新すると、同じ身元と新しい期限を示す', async () => {
  const previous = material(), updated = structuredClone(previous);
  updated.aws!.authentication = { kind: 'session', accessKeyId: 'updated-key', secretAccessKey: 'updated-secret',
    sessionToken: 'updated-session', expiresAt: Date.now() + 7_200_000 };
  updated.aws!.sourceIdentity.arn = 'arn:aws:sts::123456789012:assumed-role/Source/next-session';
  updated.aws!.identity.arn = 'arn:aws:sts::999999999999:assumed-role/Target/next-session';
  const approved = await connectionMetadata(previous), renewed = await connectionMetadata(updated);
  assert.equal(renewed.accountId, approved.accountId);
  assert.equal(renewed.accountId, 'arn:aws:sts::999999999999:assumed-role/Target');
  assert.equal(renewed.aws!.expiresAt, updated.aws!.authentication.expiresAt);
});
