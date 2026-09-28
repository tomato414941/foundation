import { AwsClient } from './client.mjs';

// Answers as AWS would for roles made with the right external ID; every other outbound request is refused.
export class FakeAws extends AwsClient {
  constructor() {
    super({ roleArn: 'arn:aws:iam::111111111111:role/foundation-host-InstanceRole', region: 'ap-northeast-1', templateBucket: 'fixture-bucket' },
      { fetcher: (url, options) => this.fetch(url, options), credentials: async () => ({ accessKeyId: 'AKIAFIXTURE', secretAccessKey: 'fixture-secret', sessionToken: 'fixture-session' }) });
    this.calls = []; this.roles = new Map(); this.assumed = 0; this.lastExternalId = null;
    // For a browser test that cannot reach this object: any role in account 222222222222 made with the latest link.
    this.lenient = false;
  }
  async prepare() {
    const started = await super.prepare();
    this.lastExternalId = started.externalId;
    return started;
  }
  // The stack the owner "made": a role that trusts the given external ID.
  make(externalId, account = '222222222222', name = 'foundation-connection-FoundationRole-ABC') {
    const arn = 'arn:aws:iam::' + account + ':role/' + name;
    this.roles.set(arn, externalId);
    return arn;
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (url.startsWith('https://fixture-bucket.s3.ap-northeast-1.amazonaws.com/') && options.method === 'PUT') return new Response('', { status: 200 });
    if (url === 'https://sts.ap-northeast-1.amazonaws.com/' && options.method === 'POST') {
      const body = new URLSearchParams(options.body);
      if (!options.headers.authorization?.startsWith('AWS4-HMAC-SHA256 Credential=AKIAFIXTURE/')) return new Response('<Error><Code>InvalidClientTokenId</Code></Error>', { status: 403 });
      const arn = body.get('RoleArn');
      if (this.lenient && arn.startsWith('arn:aws:iam::222222222222:role/') && body.get('ExternalId') === this.lastExternalId) this.roles.set(arn, this.lastExternalId);
      if (!this.roles.has(arn) || this.roles.get(arn) !== body.get('ExternalId')) return new Response('<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>', { status: 403 });
      this.assumed++;
      const expiration = new Date(Date.now() + 3600_000).toISOString();
      return new Response(`<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAASSUMED${this.assumed}</AccessKeyId><SecretAccessKey>assumed-secret-${this.assumed}</SecretAccessKey><SessionToken>assumed-session-${this.assumed}</SessionToken><Expiration>${expiration}</Expiration></Credentials><AssumedRoleUser><Arn>${arn}</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, { status: 200 });
    }
    throw new Error('Unexpected outbound request: ' + url);
  }
}
