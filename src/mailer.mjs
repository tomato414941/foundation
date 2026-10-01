import { fail } from './errors.mjs';

// Sending email, through Resend's API. Foundation decides what an email proves; this only delivers it.
export class ResendMailer {
  constructor({ key = '', from = '', fetcher = fetch } = {}) {
    Object.assign(this, { key, from, fetcher, enabled: Boolean(key && from) });
    if (Boolean(key) !== Boolean(from)) throw new Error('Both a Resend API key and a sender address are required');
  }
  async send({ to, subject, html, text }) {
    if (!this.enabled) fail(503, 'email_unavailable', '現在サインインを利用できません。');
    let response;
    try {
      response = await this.fetcher('https://api.resend.com/emails', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(12_000),
        headers: { authorization: 'Bearer ' + this.key, 'content-type': 'application/json' }, body: JSON.stringify({ from: this.from, to: [to], subject, html, text }) });
    } catch { fail(503, 'email_unavailable', 'メールを送信できませんでした。時間をおいてお試しください。'); }
    if (response.status === 429) fail(429, 'email_rate_limit', 'メール送信の上限に達しました。時間をおいてお試しください。');
    if (!response.ok) fail(503, 'email_unavailable', 'メールを送信できませんでした。時間をおいてお試しください。');
  }
}
