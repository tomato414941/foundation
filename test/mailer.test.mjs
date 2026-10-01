import test from 'node:test';
import assert from 'node:assert/strict';
import { ResendMailer } from '../src/mailer.mjs';

const mailer = (respond, sent = []) => new ResendMailer({ key: 're_test_key', from: 'Foundation <signin@example.test>',
  fetcher: async (url, options) => { sent.push({ url, options }); return respond(); } });

test('ResendのAPIに、送信元・宛先・件名・本文を送る', async () => {
  const sent = [];
  await mailer(() => new Response('{}', { status: 200 }), sent).send({ to: 'new@example.test', subject: '件名', html: '<p>本文</p>', text: '本文' });
  assert.equal(sent[0].url, 'https://api.resend.com/emails');
  assert.equal(sent[0].options.headers.authorization, 'Bearer re_test_key');
  assert.deepEqual(JSON.parse(sent[0].options.body), { from: 'Foundation <signin@example.test>', to: ['new@example.test'], subject: '件名', html: '<p>本文</p>', text: '本文' });
});

test('送信の上限と失敗を、APIキーを含めずに返す', async () => {
  await assert.rejects(mailer(() => new Response('{}', { status: 429 })).send({ to: 'a@example.test' }), { status: 429, code: 'email_rate_limit' });
  await assert.rejects(mailer(() => new Response('re_test_key', { status: 500 })).send({ to: 'a@example.test' }), error => error.status === 503 && error.code === 'email_unavailable' && !error.message.includes('re_test_key'));
  await assert.rejects(mailer(() => { throw new Error('re_test_key unreachable'); }).send({ to: 'a@example.test' }), error => error.status === 503 && !error.message.includes('re_test_key'));
});

test('キーと送信元の片方だけでは設定として受け付けず、どちらもなければ送信を断る', async () => {
  assert.throws(() => new ResendMailer({ key: 're_test_key' }));
  assert.throws(() => new ResendMailer({ from: 'signin@example.test' }));
  await assert.rejects(new ResendMailer().send({ to: 'a@example.test' }), { status: 503, code: 'email_unavailable' });
});
