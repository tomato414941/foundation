import test from 'node:test';
import assert from 'node:assert/strict';
import { awsRoleCreateUrl, AwsRoleSetup, awsRoleReturn } from '../shared/aws-setup.js';
import { completeAwsRoleSetup, consumeAwsRoleSetup, rememberAwsRoleSetup } from '../web/app/aws-role-setup.js';

const setup = () => AwsRoleSetup.parse({ id: 'f109ab1d-bdc6-4eb6-bb2a-3adfc8e831e3',
  environmentId: '4aeb4b0a-e194-44d0-8bb9-384b296acbb3',
  principalArn: 'arn:aws:iam::123456789012:role/Executor', region: 'ap-northeast-1',
  externalId: 'unique-external-id', permission: 'ReadOnlyAccess', returnUrl: 'https://foundation.test/connections/aws/complete' });
const arn = 'arn:aws:iam::999999999999:role/foundation-Example';
function callback(id = setup().id, role = arn) {
  const url = new URL(setup().returnUrl);
  url.searchParams.set('state', id);
  url.hash = new URLSearchParams({ arn: role }).toString();
  return url;
}
function storage() {
  const values = new Map<string, string>();
  return { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); }, removeItem: (key: string) => { values.delete(key); } };
}

test('選んだ権限と実行環境の身元と戻り先をAWSの作成画面へ引き継ぐ', async t => {
  for (const permission of ['ReadOnlyAccess', 'AdministratorAccess'] as const) await t.test(permission, () => {
    const input = { ...setup(), permission }, url = new URL(awsRoleCreateUrl('https://objects.example/template?signature=a&expires=3600', input));
    const parameters = new URLSearchParams(url.hash.split('?')[1]);
    assert.equal(url.searchParams.get('region'), input.region);
    assert.equal(parameters.get('templateURL'), 'https://objects.example/template?signature=a&expires=3600');
    assert.equal(parameters.get('param_PrincipalArn'), input.principalArn);
    assert.equal(parameters.get('param_ExternalId'), input.externalId);
    assert.equal(parameters.get('param_Policies'), 'arn:aws:iam::aws:policy/' + permission);
    const returnUrl = new URL(parameters.get('param_ReturnUrl')!);
    assert.equal(returnUrl.origin, 'https://foundation.test');
    assert.equal(returnUrl.pathname, '/connections/aws/complete');
    assert.equal(returnUrl.searchParams.get('state'), input.id);
  });
});

test('同じブラウザで開始したAWS設定の戻り情報を同じ接続設定へ一度だけ反映する', () => {
  const saved = storage(), input = setup();
  rememberAwsRoleSetup(input, saved, 1000);
  assert.deepEqual(completeAwsRoleSetup(callback(), saved, 2000), { id: input.id, arn });
  assert.equal(consumeAwsRoleSetup(input, saved, 2000), arn);
  assert.equal(consumeAwsRoleSetup(input, saved, 2000), null);
  assert.equal(completeAwsRoleSetup(callback(), saved, 2000), null);
});

test('AWS設定の開始元と期限と戻り情報を照合し不正な応答を拒否する', async t => {
  const invalid = [
    ['unknown setup', callback('4aeb4b0a-e194-44d0-8bb9-384b296acbb3')],
    ['invalid state', callback('invalid')],
    ['invalid role', callback(setup().id, 'arn:aws:iam::999999999999:user/Example')],
    ['different partition', callback(setup().id, 'arn:aws-cn:iam::999999999999:role/Example')],
    ['different origin', new URL(callback().href.replace('foundation.test', 'other.test'))],
    ['duplicate state', new URL(callback().href.replace('#', '&state=' + setup().id + '#'))],
    ['duplicate role', new URL(callback().href + '&arn=' + encodeURIComponent(arn))],
  ] as const;
  for (const [name, url] of invalid) await t.test(name, () => {
    const saved = storage(); rememberAwsRoleSetup(setup(), saved, 1000);
    assert.equal(completeAwsRoleSetup(url, saved, 2000), null);
    assert.equal(consumeAwsRoleSetup(setup(), saved, 2000), null);
  });
  const saved = storage(); rememberAwsRoleSetup(setup(), saved, 1000);
  assert.equal(completeAwsRoleSetup(callback(), saved, 3_601_000), null);
  assert.throws(() => awsRoleReturn(new URL(setup().returnUrl)));
});

test('AWS設定中に接続条件が変わると以前の戻り情報を新しい設定へ反映しない', async t => {
  const changes = [
    { environmentId: '5f559443-9148-4e45-bd07-6c9a21a97905' },
    { principalArn: 'arn:aws:iam::123456789012:role/Other' },
    { externalId: 'other-external-id' }, { region: 'us-west-2' }, { permission: 'AdministratorAccess' as const },
  ];
  for (const change of changes) await t.test(Object.keys(change)[0], () => {
    const saved = storage(); rememberAwsRoleSetup(setup(), saved, 1000);
    assert.ok(completeAwsRoleSetup(callback(), saved, 2000));
    assert.equal(consumeAwsRoleSetup({ ...setup(), ...change }, saved, 2000), null);
    assert.equal(consumeAwsRoleSetup(setup(), saved, 2000), arn);
  });
});
