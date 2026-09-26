import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fail } from '../../errors.mjs';
import { presignAws, serverCredentials, signAws } from '../../aws-sigv4.mjs';

export const AWS_API = 'https://sts.amazonaws.com';
export const AWS_DOCS = 'https://docs.aws.amazon.com/';
export const AWS_CONSOLE = 'https://console.aws.amazon.com/iam/home#/roles';
const ROLE_ARN = /^arn:(aws[a-z-]*):iam::(\d{12}):role\/([\w+=,.@/-]{1,200})$/;
const TEMPLATE_KEY = 'foundation/aws-connection.yaml';
const STACK_NAME = 'foundation-connection';
const SESSION_SECONDS = 3600;
const invalidResponse = () => fail(502, 'service_response', 'AWSからの応答を確認できませんでした。');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const tag = (xml, name) => { const match = new RegExp('<' + name + '>([^<]*)</' + name + '>').exec(xml); return match ? match[1] : undefined; };

// Rather than a key of the account holder's, Foundation is trusted to assume a role they made. The role names
// Foundation's own role as the only principal that may assume it, and an external ID that Foundation chose for
// this connection and checks on every use. What is kept is the role's name and that ID: nothing that works
// anywhere else, and nothing that works without Foundation's own identity.
export class AwsClient {
  constructor({ roleArn = '', region = 'ap-northeast-1', templateBucket = '' } = {}, { fetcher = fetch, credentials = () => serverCredentials(), template } = {}) {
    this.enabled = Boolean(roleArn && templateBucket);
    this.roleArn = roleArn; this.region = region; this.templateBucket = templateBucket; this.fetcher = fetcher; this.credentials = credentials;
    this.template = template ?? (() => readFileSync(new URL('../../../deploy/aws-connection.yaml', import.meta.url), 'utf8'));
  }
  check() { if (!this.enabled) fail(503, 'aws_unavailable', '現在AWSに接続できません。'); }
  // The account holder makes the role in their own console, from a template Foundation keeps in its bucket and
  // hands over as a one-hour link. The external ID is made here and travels only through that link.
  async prepare() {
    this.check();
    const externalId = randomBytes(24).toString('base64url'), credentials = await this.credentials();
    const host = this.templateBucket + '.s3.' + this.region + '.amazonaws.com', path = '/' + TEMPLATE_KEY, body = this.template();
    const put = signAws({ method: 'PUT', service: 's3', region: this.region, host, path, body, credentials,
      headers: { 'content-type': 'text/plain', 'x-amz-content-sha256': sha256(body) } });
    let response;
    try { response = await this.fetcher(put.url, { method: 'PUT', headers: put.headers, body, redirect: 'error', signal: AbortSignal.timeout(20_000) }); }
    catch { fail(502, 'service_unavailable', 'AWSに接続できませんでした。時間をおいて再度お試しください。'); }
    if (!response.ok) fail(502, 'service_response', '接続用のテンプレートを用意できませんでした。');
    const templateUrl = presignAws({ service: 's3', region: this.region, host, path, expires: 3600, credentials });
    const url = new URL('https://console.aws.amazon.com/cloudformation/home');
    url.search = new URLSearchParams({ region: this.region }).toString();
    url.hash = '/stacks/create/review?' + new URLSearchParams({ templateURL: templateUrl, stackName: STACK_NAME, param_FoundationRoleArn: this.roleArn, param_ExternalId: externalId }).toString();
    return { url: url.href, externalId };
  }
  parseRole(value) {
    const match = typeof value === 'string' ? ROLE_ARN.exec(value.trim()) : null;
    if (!match) fail(400, 'invalid_role', '役割のARN (arn:aws:iam::123456789012:role/...) を貼り付けてください。');
    return { arn: value.trim(), partition: match[1], account: match[2], name: match[3] };
  }
  // Assuming the role is both the check that it was made for Foundation and the way credentials are obtained.
  async assume({ roleArn, externalId }) {
    this.check();
    const role = this.parseRole(roleArn), credentials = await this.credentials();
    const body = new URLSearchParams({ Action: 'AssumeRole', Version: '2011-06-15', RoleArn: role.arn, RoleSessionName: 'foundation', ExternalId: externalId, DurationSeconds: String(SESSION_SECONDS) }).toString();
    const host = 'sts.' + this.region + '.amazonaws.com';
    const request = signAws({ service: 'sts', region: this.region, host, body, credentials, headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' } });
    let response, text;
    try {
      response = await this.fetcher(request.url, { method: 'POST', headers: request.headers, body, redirect: 'error', signal: AbortSignal.timeout(20_000) });
      text = await response.text();
    } catch { fail(502, 'service_unavailable', 'AWSに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 403 || /AccessDenied|InvalidClientTokenId/.test(text)) fail(409, 'reconnect_required', 'AWSがこの役割の利用を認めませんでした。役割がFoundation向けに作られているか確認してください。');
    if (!response.ok) invalidResponse();
    const accessKeyId = tag(text, 'AccessKeyId'), secretAccessKey = tag(text, 'SecretAccessKey'), sessionToken = tag(text, 'SessionToken'), expiration = Date.parse(tag(text, 'Expiration') ?? '');
    if (!accessKeyId || !secretAccessKey || !sessionToken || !Number.isFinite(expiration)) invalidResponse();
    return { role, accessKeyId, secretAccessKey, sessionToken, expiresAt: expiration };
  }
}
