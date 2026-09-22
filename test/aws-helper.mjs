import { AwsClient, signedRequest } from '../src/services/aws.mjs';
import { awsIamUserKey, gmailOauth } from '../src/adapters.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export const AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
export const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
export const AWS_FIELDS = { access_key_id: AWS_KEY_ID, role_arn: 'arn:aws:iam::123456789012:role/foundation-agent', region: 'ap-northeast-1' };
export const AWS_CODE = [AWS_KEY_ID, AWS_SECRET, AWS_FIELDS.role_arn, AWS_FIELDS.region].join('|');

// Re-signs each request with the known secret and compares signatures, as STS would; never contacts AWS.
export class FakeAws extends AwsClient {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
    this.calls = []; this.maxDuration = 3600; this.trusted = true; this.identity = { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:user/foundation', UserId: 'AIDAEXAMPLE' };
  }
  async fetch(url, options) {
    const params = Object.fromEntries(new URLSearchParams(options.body));
    this.calls.push({ url, params, headers: options.headers });
    if (url !== 'https://sts.ap-northeast-1.amazonaws.com/' || options.method !== 'POST') throw new Error('Unexpected STS endpoint in tests: ' + url);
    if (this.handler) return this.handler(url, options, params);
    const amzDate = options.headers['x-amz-date'], now = new Date(amzDate.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, '$1-$2-$3T$4:$5:$6Z'));
    const expected = signedRequest({ accessKeyId: AWS_KEY_ID, secretAccessKey: AWS_SECRET, region: 'ap-northeast-1', params, now }).headers.authorization;
    if (!options.headers.authorization.startsWith('AWS4-HMAC-SHA256 Credential=' + AWS_KEY_ID + '/') || options.headers.authorization !== expected) return json({ Error: { Code: 'InvalidClientTokenId' } }, 403);
    if (params.Action === 'GetCallerIdentity') return json({ GetCallerIdentityResponse: { GetCallerIdentityResult: this.identity } });
    if (params.Action === 'AssumeRole') {
      if (!this.trusted) return json({ Error: { Code: 'AccessDenied', Message: 'User is not authorized to perform: sts:AssumeRole' } }, 403);
      const duration = params.DurationSeconds ? Number(params.DurationSeconds) : 3600;
      if (duration > this.maxDuration || duration < 900) return json({ Error: { Code: 'ValidationError', Message: 'The requested DurationSeconds exceeds the MaxSessionDuration set for this role.' } }, 400);
      return json({ AssumeRoleResponse: { AssumeRoleResult: { Credentials: { AccessKeyId: 'ASIAEXAMPLE1234567890'.slice(0, 20), SecretAccessKey: 'temporary/secret/' + params.RoleSessionName, SessionToken: 'session-token-' + duration, Expiration: Math.floor(Date.now() / 1000) + duration } } } });
    }
    return json({ Error: { Code: 'InvalidAction' } }, 400);
  }
}

export async function awsFixture(t, options = {}) {
  const aws = options.aws || new FakeAws(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, adapters: [awsIamUserKey(aws), gmailOauth(gmail)], ...options });
  const importAws = ({ token = AWS_CODE, ...extra } = {}) => f.request('/api/adapters/aws.iam-user-key/connect', { method: 'POST', data: { name: 'AWS', permission: 'assume-role', values: { code: token }, ...extra } });
  async function awsAccount(extra = {}) {
    const result = await importAws(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.accounts.find(account => account.id === result.json.account_id);
  }
  return { ...f, aws, importAws, awsAccount };
}
