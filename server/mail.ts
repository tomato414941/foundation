export interface Mailer {
  readonly enabled: boolean;
  send(address: string, link: string, locale: 'ja' | 'en'): Promise<void>;
  // A code that confirms one change, entered wherever the change is being made.
  sendCode(address: string, code: string, locale: 'ja' | 'en'): Promise<void>;
}
export class ResendMailer implements Mailer {
  readonly enabled: boolean;
  constructor(
    private readonly apiKey: string,
    private readonly from: string,
  ) {
    this.enabled = Boolean(apiKey && from);
  }
  async send(address: string, link: string, locale: 'ja' | 'en') {
    await this.deliver(address, locale === 'ja' ? 'Foundationへのサインイン' : 'Sign in to Foundation',
      locale === 'ja'
        ? `次のリンクを開いて続けてください。リンクは15分間有効です。\n\n${link}\n\n心当たりがなければ、このメールを無視してください。`
        : `Open this link to continue. It expires in 15 minutes.\n\n${link}\n\nIf you did not request this email, you can ignore it.`);
  }
  async sendCode(address: string, code: string, locale: 'ja' | 'en') {
    await this.deliver(address, locale === 'ja' ? 'Foundationの変更の確認コード' : 'Confirmation code for a Foundation change',
      locale === 'ja'
        ? `サインイン方法や鍵の変更を確認するコードです。10分間有効です。\n\n${code}\n\n心当たりがなければ、このコードを誰にも伝えず、サインイン方法を確認してください。`
        : `This code confirms a change to sign-in methods or keys. It expires in 10 minutes.\n\n${code}\n\nIf you did not make this change, do not share the code, and review your sign-in methods.`);
  }
  private async deliver(address: string, subject: string, text: string) {
    if (!this.enabled) throw new Error('Email is not configured.');
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + this.apiKey, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(15_000),
      body: JSON.stringify({ from: this.from, to: [address], subject, text }),
    });
    if (!response.ok) throw new Error('The email could not be sent.');
  }
}
