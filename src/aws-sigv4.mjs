import { createHash, createHmac } from 'node:crypto';

const digest = value => createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();

const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16).toUpperCase());
const stamp = now => { const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''); return { amzDate, date: amzDate.slice(0, 8) }; };
const signature = (credentials, date, region, service, toSign) => createHmac('sha256', hmac(hmac(hmac(hmac('AWS4' + credentials.secretAccessKey, date), region), service), 'aws4_request')).update(toSign).digest('hex');

// AWS Signature Version 4 for a request to a regional service endpoint. Kept here so Foundation needs no AWS SDK.
// `credentials` may carry a session token (temporary credentials from a role); it is then signed as well.
// `path` is sent as given, so it must already be in canonical (URI-encoded) form.
export function signAws({ method = 'POST', service, region, host, path = '/', body, headers = {}, credentials, now = new Date() }) {
  const { amzDate, date } = stamp(now);
  const all = { host, 'x-amz-date': amzDate, ...Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])) };
  if (credentials.sessionToken) all['x-amz-security-token'] = credentials.sessionToken;
  const names = Object.keys(all).sort(), signedHeaders = names.join(';');
  const canonical = [method, path, '', ...names.map(name => name + ':' + String(all[name]).trim()), '', signedHeaders, digest(body)].join('\n');
  const scope = date + '/' + region + '/' + service + '/aws4_request';
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, digest(canonical)].join('\n');
  return { url: 'https://' + host + path, method, body, headers: { ...all, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature(credentials, date, region, service, toSign)}` } };
}

// A presigned URL: whoever holds it may make this one request until it expires (or the signing credentials do).
export function presignAws({ method = 'GET', service, region, host, path, expires, credentials, now = new Date() }) {
  const { amzDate, date } = stamp(now), scope = date + '/' + region + '/' + service + '/aws4_request';
  const query = { 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': credentials.accessKeyId + '/' + scope, 'X-Amz-Date': amzDate, 'X-Amz-Expires': String(expires), 'X-Amz-SignedHeaders': 'host',
    ...(credentials.sessionToken ? { 'X-Amz-Security-Token': credentials.sessionToken } : {}) };
  const canonicalQuery = Object.keys(query).sort().map(name => encode(name) + '=' + encode(query[name])).join('&');
  const canonical = [method, path, canonicalQuery, 'host:' + host, '', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, digest(canonical)].join('\n');
  return 'https://' + host + path + '?' + canonicalQuery + '&X-Amz-Signature=' + signature(credentials, date, region, service, toSign);
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
