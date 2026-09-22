import { createHash, createHmac } from 'node:crypto';

const digest = value => createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();

// AWS Signature Version 4 for a POST to a regional service endpoint. Kept here so Foundation needs no AWS SDK.
// `credentials` may carry a session token (temporary credentials from a role); it is then signed as well.
export function signAws({ service, region, host, path = '/', body, headers = {}, credentials, now = new Date() }) {
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''), date = amzDate.slice(0, 8);
  const all = { host, 'x-amz-date': amzDate, ...Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])) };
  if (credentials.sessionToken) all['x-amz-security-token'] = credentials.sessionToken;
  const names = Object.keys(all).sort(), signedHeaders = names.join(';');
  const canonical = ['POST', path, '', ...names.map(name => name + ':' + String(all[name]).trim()), '', signedHeaders, digest(body)].join('\n');
  const scope = date + '/' + region + '/' + service + '/aws4_request';
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, digest(canonical)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + credentials.secretAccessKey, date), region), service), 'aws4_request');
  const signature = createHmac('sha256', signingKey).update(toSign).digest('hex');
  return { url: 'https://' + host + path, method: 'POST', body, headers: { ...all, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` } };
}

// Where the server itself gets AWS credentials: the environment (for example under `foundation exec`),
// or the EC2 instance role through IMDSv2. Never a file.
export async function serverCredentials({ fetcher = fetch, env = process.env } = {}) {
  if (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) return { accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY, sessionToken: env.AWS_SESSION_TOKEN || undefined };
  const base = 'http://169.254.169.254/latest';
  const token = await (await fetcher(base + '/api/token', { method: 'PUT', headers: { 'x-aws-ec2-metadata-token-ttl-seconds': '300' }, signal: AbortSignal.timeout(2_000) })).text();
  const headers = { 'x-aws-ec2-metadata-token': token };
  const role = (await (await fetcher(base + '/meta-data/iam/security-credentials/', { headers, signal: AbortSignal.timeout(2_000) })).text()).trim().split('\n')[0];
  if (!role) throw new Error('No instance role is attached; Foundation cannot reach KMS.');
  const data = await (await fetcher(base + '/meta-data/iam/security-credentials/' + role, { headers, signal: AbortSignal.timeout(2_000) })).json();
  if (data.Code !== 'Success' || !data.AccessKeyId || !data.SecretAccessKey || !data.Token) throw new Error('The instance role did not return credentials.');
  return { accessKeyId: data.AccessKeyId, secretAccessKey: data.SecretAccessKey, sessionToken: data.Token };
}
