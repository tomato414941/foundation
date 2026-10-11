import test from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionMaterial, connectionLabels, connectionMetadata } from '../shared/connections.js';
import { connectionAuthorization } from '../shared/connection-authorization.js';
import { connectionFacts } from '../shared/connection-facts.js';
import { AwsConnection } from '../runtime/aws-connection.js';
import { OAuthConnection } from '../runtime/oauth-connection.js';
import { TokenConnection } from '../runtime/token-connection.js';

const base = { format: 2, generation: 'f109ab1d-bdc6-4eb6-bb2a-3adfc8e831e3', appId: null, appGeneration: null };
const identity = { accountId: '123456789012', principalId: 'EXAMPLE', arn: 'arn:aws:iam::123456789012:user/Example' };
const materials = () => [
  ConnectionMaterial.parse({ ...base, methodId: 'example:oauth',
    method: { name: 'OAuth', kind: 'oauth', config: { application: 'implicit',
      authorizeUrl: 'https://example.com/authorize', tokenUrl: 'https://example.com/token' } },
    oauth: { accessToken: 'private-access-token', refreshToken: 'private-refresh-token', expiresAt: null,
      account: 'account-1', accountName: 'Account', accountVerified: true,
      scopes: ['write', 'read'], scopesStatus: 'reported', extra: { secret: 'private-extra' }, facts: {} } }),
  ConnectionMaterial.parse({ ...base, methodId: 'example:token',
    method: { name: 'Token', kind: 'token', config: { fields: [{ name: 'token', label: 'Token' }], outputs: { TOKEN: '/token' } } },
    fields: { token: 'private-token' } }),
  ConnectionMaterial.parse({ ...base, methodId: 'aws:authentication',
    method: { name: 'AWS', kind: 'aws', config: {} },
    aws: { authentication: { kind: 'access_key', accessKeyId: 'private-key-id', secretAccessKey: 'private-secret-key' },
      region: 'us-west-2', sourceIdentity: identity, identity } }),
];

test('認証方式に対応する認証情報とアプリだけを受け付ける', async t => {
  const states = materials();
  for (const state of states) await t.test(state.method.kind, () => {
    assert.equal(ConnectionMaterial.safeParse(state).success, true);
    for (const other of states.filter(value => value.method.kind !== state.method.kind)) {
      const key = other.method.kind === 'token' ? 'fields' : other.method.kind;
      assert.equal(ConnectionMaterial.safeParse({ ...state, [key]: other[key] }).success, false);
    }
    if (state.method.kind !== 'oauth') assert.equal(ConnectionMaterial.safeParse({ ...state,
      appId: base.generation, appGeneration: base.generation }).success, false);
  });
});

test('各方式のProviderが秘密を含まない確認結果を返し、承認と表示に同じ身元を使う', async t => {
  const providers = {
    oauth: new OAuthConnection({ send: async () => { throw new Error('Not used by observations.'); } }),
    token: new TokenConnection(),
    aws: new AwsConnection({ obtain: async () => { throw new Error('Not used by observations.'); } }),
  };
  for (const state of materials()) await t.test(state.method.kind, async () => {
    const facts = providers[state.method.kind].facts(state), metadata = await connectionMetadata(state, facts);
    assert.deepEqual(facts, connectionFacts(state));
    assert.equal(JSON.stringify(facts).includes('private-'), false);
    assert.equal(connectionAuthorization(state, facts).account, metadata.accountId);
    assert.equal(connectionLabels(state, facts).account, facts.accountName);
    assert.deepEqual(metadata.scopes, facts.scopes);
  });
});

test('身元が未確認の認証情報を保存しても確認済みアカウントとして表示しない', async () => {
  const oauth = materials()[0]!;
  const state = ConnectionMaterial.parse({ ...oauth, oauth: { ...oauth.oauth!, accountVerified: false } });
  const facts = connectionFacts(state), metadata = await connectionMetadata(state);
  assert.equal(facts.accountVerified, false);
  assert.equal(metadata.accountId, null);
  assert.equal(metadata.accountVerified, false);
  assert.equal(connectionAuthorization(state).account, 'account-1');
});
