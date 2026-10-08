import test from 'node:test';
import assert from 'node:assert/strict';
import { awsPrincipal } from '../runtime/roles.js';

test('実行先の呼び出し元の身元から、ロールが信頼すべきIAMのロールまたはユーザーを求める', () => {
  assert.equal(awsPrincipal('arn:aws:sts::123456789012:assumed-role/foundation-host/i-0abc'),
    'arn:aws:iam::123456789012:role/foundation-host');
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:role/service/foundation-host'),
    'arn:aws:iam::123456789012:role/service/foundation-host');
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:user/operator'), 'arn:aws:iam::123456789012:user/operator');
  assert.equal(awsPrincipal('arn:aws:iam::123456789012:root'), null);
  assert.equal(awsPrincipal('arn:aws:sts::123456789012:federated-user/guest'), null);
});
