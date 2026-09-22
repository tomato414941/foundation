import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';
import { signAws } from '../aws-sigv4.mjs';

export const AWS_DOCS = 'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html';
export const AWS_KEYS = 'https://console.aws.amazon.com/iam/home#/security_credentials';
export const AWS_SCOPE = 'aws:assume-role';
export const AWS_TEMPLATE_PATH = '/aws/foundation-agent.yaml';
export const AWS_PERMISSION_SETS = ['arn:aws:iam::aws:policy/ReadOnlyAccess', 'arn:aws:iam::aws:policy/PowerUserAccess', 'arn:aws:iam::aws:policy/AdministratorAccess'];

// One stack creates everything the user would otherwise assemble by hand: a user that may
// only assume one role, the role the AI will use, and an access key. The outputs are what
// the registration dialog asks for. Resources are unnamed so only CAPABILITY_IAM is needed.
export function cloudFormationTemplate() {
  return `AWSTemplateFormatVersion: '2010-09-09'
Description: Foundation agent access - an IAM user that can only assume one role, and the role an approved AI uses through Foundation.
Parameters:
  Permissions:
    Type: String
    Default: ${AWS_PERMISSION_SETS[1]}
    AllowedValues:
${AWS_PERMISSION_SETS.map(arn => '      - ' + arn).join('\n')}
    Description: What the AI may do through the role (ReadOnlyAccess, PowerUserAccess, or AdministratorAccess).
Resources:
  FoundationUser:
    Type: AWS::IAM::User
  AgentRole:
    Type: AWS::IAM::Role
    Properties:
      Description: Assumed by Foundation on behalf of an approved AI. Temporary credentials only.
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !GetAtt FoundationUser.Arn
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - !Ref Permissions
  AssumeAgentRole:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: foundation-assume-agent-role
      Users:
        - !Ref FoundationUser
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: sts:AssumeRole
            Resource: !GetAtt AgentRole.Arn
  FoundationKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref FoundationUser
Outputs:
  CopyToFoundation:
    Description: Copy this whole value into Foundation. It contains the access key, the role and the region.
    Value: !Join ['|', [!Ref FoundationKey, !GetAtt FoundationKey.SecretAccessKey, !GetAtt AgentRole.Arn, !Ref AWS::Region]]
`;
}

export function quickCreateUrl(templateUrl, region) {
  if (!templateUrl) return null;
  const target = new URL(templateUrl);
  if (target.protocol !== 'https:' || !/(^|\.)amazonaws\.com$/.test(target.hostname)) throw new Error('FOUNDATION_AWS_TEMPLATE_URL must be an HTTPS S3 URL');
  return `https://${region}.console.aws.amazon.com/cloudformation/home?region=${region}#/stacks/quickcreate?templateURL=${encodeURIComponent(target.href)}&stackName=foundation`;
}
const STS_VERSION = '2011-06-15';
const digest = value => createHash('sha256').update(value).digest('hex');
const invalidResponse = () => fail(502, 'service_response', 'AWSからの応答を確認できませんでした。');

// STS query API over the generic signer.
export function signedRequest({ accessKeyId, secretAccessKey, region, params, now = new Date() }) {
  return signAws({ service: 'sts', region, host: 'sts.' + region + '.amazonaws.com', body: new URLSearchParams(params).toString(), credentials: { accessKeyId, secretAccessKey },
    headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', accept: 'application/json' }, now });
}

// Foundation keeps the long-lived IAM user key and hands runtimes only temporary
// credentials for one role. How long they last is between the runtime and AWS:
// a requested duration is passed through untouched, none means AWS's default.
export class AwsClient {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'aws_unavailable', '現在AWSに接続できません。'); }
  fields(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_account', 'アクセスキーID、ロールARN、リージョンを入力してください。');
    const accessKeyId = String(input.access_key_id ?? '').trim(), roleArn = String(input.role_arn ?? '').trim(), region = String(input.region ?? '').trim().toLowerCase();
    if (!/^AKIA[A-Z0-9]{16}$/.test(accessKeyId)) fail(400, 'invalid_account', 'アクセスキーIDは AKIA で始まる20文字です。一時認証情報 (ASIA...) は登録できません。');
    if (!/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@\/-]{1,128}$/.test(roleArn)) fail(400, 'invalid_account', 'ロールARNの形式を確認してください (arn:aws:iam::123456789012:role/名前)。');
    if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(region)) fail(400, 'invalid_account', 'リージョンは ap-northeast-1 のような形式です。');
    return { access_key_id: accessKeyId, role_arn: roleArn, region };
  }
  async call(key, action, params = {}) {
    const request = signedRequest({ accessKeyId: key.access_key_id, secretAccessKey: key.secret, region: key.region, params: { Action: action, Version: STS_VERSION, ...params } });
    let response;
    try { response = await this.fetcher(request.url, { method: request.method, headers: request.headers, body: request.body, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'AWSに接続できませんでした。時間をおいて再度お試しください。'); }
    let data;
    try { data = await response.json(); } catch { data = null; }
    if (response.status === 403) {
      const code = data?.Error?.Code;
      if (action === 'AssumeRole' && code === 'AccessDenied') fail(409, 'role_denied', 'このキーではロールを引き受けられません。ロールの信頼ポリシーと、ユーザーの sts:AssumeRole 権限を確認してください。');
      fail(409, 'reconnect_required', 'AWSがこのアクセスキーを受け付けませんでした。キーが無効化・削除されていないか確認してください。');
    }
    if (response.status === 400 && data?.Error?.Code) {
      // Validation errors (for example a duration above the role's limit) are AWS's decision; pass the code through.
      const error = new HttpError(409, 'aws_' + String(data.Error.Code).replace(/[^A-Za-z]/g, '').toLowerCase(), 'AWSが要求を拒否しました: ' + String(data.Error.Code).slice(0, 64));
      throw error;
    }
    if (response.status === 429 || data?.Error?.Code === 'Throttling') fail(503, 'service_rate_limit', 'AWSへの要求が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'service_unavailable', 'AWSで処理を完了できませんでした。');
    if (!data || typeof data !== 'object') invalidResponse();
    return data;
  }
  parse(code) {
    const parts = typeof code === 'string' ? code.trim().split('|').map(part => part.trim()) : [];
    if (parts.length !== 4) fail(400, 'invalid_credential', 'AWSの「出力」タブに表示された CopyToFoundation の値を、そのまま貼り付けてください。');
    const [access_key_id, secret, role_arn, region] = parts;
    const fields = this.fields({ access_key_id, role_arn, region });
    if (!/^[A-Za-z0-9+/]{40}$/.test(secret)) fail(400, 'invalid_credential', 'AWSの「出力」タブに表示された CopyToFoundation の値を、そのまま貼り付けてください。');
    return { ...fields, secret };
  }
  async inspect(code) {
    const key = this.parse(code), { secret, ...fields } = key;
    const identity = (await this.call(key, 'GetCallerIdentity')).GetCallerIdentityResponse?.GetCallerIdentityResult;
    if (!identity || !/^\d{12}$/.test(identity.Account || '') || typeof identity.Arn !== 'string' || identity.Arn.length > 2048) invalidResponse();
    if (!fields.role_arn.includes(':' + identity.Account + ':')) fail(409, 'role_denied', 'ロールARNのアカウントIDが、このアクセスキーのアカウントと一致しません。');
    // Prove the trust policy once so a wrong role fails at registration, not at first use. The session is discarded.
    await this.assume(key, 'foundation-check', {});
    return { access_token: secret, credential_type: 'api_key', expires_at: null, expiry_known: false, scopes: [AWS_SCOPE],
      details: { ...fields, key_hash: digest(secret), account_id: identity.Account, user_arn: identity.Arn, checked_at: Date.now() } };
  }
  async assume(key, sessionName, { duration } = {}) {
    const params = { RoleArn: key.role_arn, RoleSessionName: sessionName };
    if (duration !== undefined) {
      if (!Number.isInteger(duration) || duration < 1) fail(400, 'invalid_duration', '期間は秒数の整数で指定してください。');
      params.DurationSeconds = String(duration);
    }
    const result = (await this.call(key, 'AssumeRole', params)).AssumeRoleResponse?.AssumeRoleResult?.Credentials;
    const expiresAt = typeof result?.Expiration === 'number' ? result.Expiration * 1000 : Date.parse(result?.Expiration || '');
    if (!result || !/^ASIA[A-Z0-9]{16}$/.test(result.AccessKeyId || '') || typeof result.SecretAccessKey !== 'string' || typeof result.SessionToken !== 'string' || !Number.isFinite(expiresAt) || /[\r\n\x00]/.test(result.SecretAccessKey + result.SessionToken)) invalidResponse();
    return { access_key_id: result.AccessKeyId, secret_access_key: result.SecretAccessKey, session_token: result.SessionToken, expires_at: expiresAt };
  }
  async importToken({ values, permission }) {
    const token = values.code;
    this.check();
    if (permission !== 'assume-role') fail(400, 'invalid_permission', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token);
    return { subject: credentials.details.account_id + ':' + credentials.details.role_arn.split('/').pop() + ':' + credentials.details.key_hash.slice(0, 12), credentials };
  }
  // Issuance never returns the stored key: each call assumes the role afresh.
  async token(store, account, force = false, options = {}) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'AWSのアクセスキーを確認し、新しい接続を追加してください。');
    const stored = store.secrets(account), key = { ...stored.details, secret: stored.access_token };
    try {
      const session = await this.assume(key, 'foundation-' + account.id.slice(0, 8), { duration: options.duration });
      return { access_token: session.secret_access_key, credential_type: 'aws_temporary', expires_at: session.expires_at, expiry_known: true, scopes: stored.scopes,
        details: { ...stored.details, session_access_key_id: session.access_key_id, session_token: session.session_token }, verification: stored.verification };
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: detail.account_id + ' / ' + detail.role_arn.split('/').pop(), credential_type: 'api_key', expires_at: null, expiry_known: false, management_url: AWS_KEYS,
      aws: { account_id: detail.account_id, role_arn: detail.role_arn, region: detail.region, user_arn: detail.user_arn }, checked_at: detail.checked_at };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'アクセスキーの無効化はIAMの画面で行ってください。'); }
}
