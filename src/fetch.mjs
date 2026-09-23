import { request as httpsRequest, Agent } from 'node:https';
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { gunzipSync, inflateSync, brotliDecompressSync } from 'node:zlib';
import { fail } from './errors.mjs';

// One HTTPS request sent on behalf of an agent that cannot run a command, with what is kept put into its headers
// or body where the agent wrote {{foundation:<path>}}. The agent never sees those values: they are substituted
// here, and taken back out of whatever comes back. What it can do is what a command given the same values could
// do, and no more: the network it reaches is the public internet, never this host or anything beside it.
export const FETCH_BODY_MAX = 1024 * 1024;
const TIMEOUT = 20_000;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const PLACEHOLDER = /\{\{foundation:([^{}]{1,300})\}\}/g;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/;
// Headers that describe the connection rather than the request. Foundation sets them itself.
// accept-encoding too: a compressed answer would carry a reflected value past the redaction below.
const OWN_HEADERS = new Set(['host', 'accept-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'expect',
  'proxy-authorization', 'proxy-connection', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip']);
const HOP_HEADERS = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authenticate']);

// Everything that is not the public internet: this machine, its network, the cloud's metadata service, and
// the ranges no public host lives in.
const INTERNAL = new BlockList();
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) INTERNAL.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
  ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]]) INTERNAL.addSubnet(address, prefix, 'ipv6');
export const isPublicAddress = (address, family = isIP(address)) => (family === 4 || family === 6) && !INTERNAL.check(address, family === 4 ? 'ipv4' : 'ipv6');

export function destination(value, ownHosts = []) {
  let url;
  try { url = new URL(value); } catch { fail(400, 'invalid_url', '送り先は https:// で始まるURLで指定してください。'); }
  if (url.protocol !== 'https:' || (url.port && url.port !== '443') || url.username || url.password) fail(400, 'invalid_url', '送り先は https:// で始まるURLで指定してください（ポートは443のみ）。');
  const host = url.hostname.toLowerCase();
  if (isIP(host.replace(/^\[|\]$/g, '')) || !host.includes('.') || host.endsWith('.local') || host.endsWith('.internal') || host === 'localhost' || host.endsWith('.localhost')) fail(400, 'invalid_destination', '送り先はインターネット上のホスト名で指定してください。');
  if (ownHosts.includes(host)) fail(400, 'invalid_destination', 'Foundation 自身には送れません。APIを直接呼んでください。');
  let decoded = url.href;
  try { decoded = decodeURIComponent(url.href); } catch {}
  if (/\{\{foundation:/.test(String(value)) || /\{\{foundation:/.test(decoded)) fail(400, 'secret_in_url', '保管したものはURLには入れられません。ヘッダか本文で使ってください。');
  return url;
}

// The paths an agent named, in the order it named them.
export function placeholders(input) {
  const found = new Set();
  const scan = text => { for (const match of String(text).matchAll(PLACEHOLDER)) found.add(match[1]); };
  for (const value of Object.values(input.headers || {})) scan(value);
  if (typeof input.body === 'string' && input.body_encoding !== 'base64') scan(input.body);
  return [...found];
}

export function prepare(input, ownHosts = []) {
  if (!input || typeof input !== 'object') fail(400, 'invalid_request', '送るリクエストを指定してください。');
  const url = destination(input.url, ownHosts);
  const method = String(input.method || 'GET').toUpperCase();
  if (!METHODS.has(method)) fail(400, 'invalid_method', 'method は GET / HEAD / POST / PUT / PATCH / DELETE のいずれかです。');
  const headers = input.headers ?? {};
  if (typeof headers !== 'object' || Array.isArray(headers) || Object.keys(headers).length > 50) fail(400, 'invalid_headers', 'headers は50件までのオブジェクトで指定してください。');
  for (const [name, value] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name) || OWN_HEADERS.has(name.toLowerCase()) || name.toLowerCase().startsWith('proxy-')) fail(400, 'invalid_headers', `ヘッダ ${name} は指定できません。`);
    if (typeof value !== 'string' || value.length > 8192 || /[\r\n\0]/.test(value)) fail(400, 'invalid_headers', `ヘッダ ${name} の値が不正です。`);
  }
  if (input.body !== undefined && typeof input.body !== 'string') fail(400, 'invalid_body', 'body は文字列で指定してください。');
  if (input.body_encoding !== undefined && !['utf8', 'base64'].includes(input.body_encoding)) fail(400, 'invalid_body', 'body_encoding は utf8 か base64 です。');
  if (input.body !== undefined && ['GET', 'HEAD'].includes(method)) fail(400, 'invalid_body', `${method} には body を付けられません。`);
  const paths = placeholders(input);
  if (paths.length > 8) fail(400, 'too_many_secrets', '1回に使えるのは8件までです。');
  return { url, method, headers, body: input.body, bodyEncoding: input.body_encoding || 'utf8', paths };
}

// Every form a value could come back in that an agent could read it from.
function forms(value) {
  const bytes = Buffer.from(value, 'utf8');
  return [...new Set([value, bytes.toString('base64'), bytes.toString('base64url'), encodeURIComponent(value), JSON.stringify(value).slice(1, -1)])]
    .filter(Boolean).map(text => Buffer.from(text, 'utf8')).sort((a, b) => b.length - a.length);
}
export function redact(buffer, values) {
  const patterns = values.flatMap(forms), mark = Buffer.from('[redacted]');
  let out = buffer;
  for (const pattern of patterns) {
    const parts = [];
    let from = 0, at;
    while ((at = out.indexOf(pattern, from)) !== -1) { parts.push(out.subarray(from, at), mark); from = at + pattern.length; }
    if (parts.length) { parts.push(out.subarray(from)); out = Buffer.concat(parts); }
  }
  return out;
}

// A public address is not enough: Foundation's own public address, reached under another name, would let a key
// kept here call this API and have what it returns handed back unredacted.
async function publicAddress(host, resolve, ownHosts) {
  let addresses;
  try { addresses = await resolve(host); } catch { fail(502, 'unresolvable', `${host} を名前解決できませんでした。`); }
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address, item.family))) fail(400, 'invalid_destination', '送り先がインターネット上のアドレスではありません。');
  const own = new Set();
  for (const name of ownHosts) { try { for (const item of await resolve(name)) own.add(item.address); } catch {} }
  if (addresses.some(item => own.has(item.address))) fail(400, 'invalid_destination', 'Foundation 自身には送れません。APIを直接呼んでください。');
  return addresses[0];
}

// Sends it. Values are put in only now, the connection goes to the address that was checked (so a name that
// resolves differently a moment later changes nothing), redirects are handed back rather than followed, and the
// answer is capped and cleaned of every value that went out.
export async function send(prepared, values, { resolve = host => lookup(host, { all: true, verbatim: true }), createConnection, ca, ownHosts = [] } = {}) {
  const fill = text => text.replace(PLACEHOLDER, (_, path) => values.get(path));
  const headers = {};
  for (const [name, value] of Object.entries(prepared.headers)) {
    const filled = fill(value);
    if (/[\r\n\0]/.test(filled) || filled.length > 16384) fail(400, 'invalid_headers', `ヘッダ ${name} に入れた値が、ヘッダには使えない形です。`);
    headers[name] = filled;
  }
  const body = prepared.body === undefined ? undefined
    : prepared.bodyEncoding === 'base64' ? Buffer.from(prepared.body, 'base64') : Buffer.from(fill(prepared.body), 'utf8');
  if (body && body.length > FETCH_BODY_MAX) fail(413, 'body_too_large', '送る内容は1MBまでです。');
  const host = prepared.url.hostname.toLowerCase();
  const address = await publicAddress(host, resolve, ownHosts.filter(name => !isIP(name)));
  const secrets = [...values.values()];
  return new Promise((resolveAnswer, reject) => {
    const outgoing = httpsRequest({ host: address.address, family: address.family, port: 443, servername: host, method: prepared.method,
      path: prepared.url.pathname + prepared.url.search, headers: { 'user-agent': 'Foundation', ...headers, host: prepared.url.host, 'accept-encoding': 'identity', ...(body ? { 'content-length': body.length } : {}) },
      ...(ca ? { ca } : {}), agent: createConnection ? Object.assign(new Agent({ keepAlive: false }), { createConnection }) : false, timeout: TIMEOUT }, incoming => {
      const chunks = []; let length = 0;
      incoming.on('data', chunk => {
        length += chunk.length;
        if (length > FETCH_BODY_MAX) { incoming.destroy(); outgoing.destroy(); reject(Object.assign(new Error('too large'), { tooLarge: true })); return; }
        chunks.push(chunk);
      });
      incoming.on('error', reject);
      incoming.on('end', () => {
        // Compressed anyway: opened here, so what is taken out is taken out of what the agent would read.
        let raw = Buffer.concat(chunks);
        const encoding = String(incoming.headers['content-encoding'] || 'identity').toLowerCase().trim();
        try {
          const limit = { maxOutputLength: FETCH_BODY_MAX };
          if (['gzip', 'x-gzip'].includes(encoding)) raw = gunzipSync(raw, limit);
          else if (encoding === 'deflate') raw = inflateSync(raw, limit);
          else if (encoding === 'br') raw = brotliDecompressSync(raw, limit);
          else if (encoding !== 'identity') return reject(Object.assign(new Error('encoding'), { encoding: true }));
        } catch { return reject(Object.assign(new Error('too large'), { tooLarge: true })); }
        const content = redact(raw, secrets);
        const answerHeaders = {};
        for (const [name, value] of Object.entries(incoming.headers)) {
          if (HOP_HEADERS.has(name) || name === 'content-encoding' || name === 'content-length') continue;
          answerHeaders[name] = redact(Buffer.from(Array.isArray(value) ? value.join(', ') : String(value)), secrets).toString('utf8');
        }
        const text = /^(text\/|application\/(json|xml|[a-z.+-]*\+(json|xml))|application\/x-www-form-urlencoded)/i.test(incoming.headers['content-type'] || '') && !content.toString('utf8').includes('�');
        resolveAnswer({ status: incoming.statusCode, headers: answerHeaders, body: text ? content.toString('utf8') : content.toString('base64'), body_encoding: text ? 'utf8' : 'base64' });
      });
    });
    const deadline = setTimeout(() => outgoing.destroy(Object.assign(new Error('timeout'), { timedOut: true })), TIMEOUT);
    outgoing.on('timeout', () => outgoing.destroy(Object.assign(new Error('timeout'), { timedOut: true })));
    outgoing.on('error', reject);
    outgoing.on('close', () => clearTimeout(deadline));
    outgoing.end(body);
  }).catch(error => {
    if (error?.status) throw error;
    if (error?.tooLarge) fail(502, 'response_too_large', '応答が1MBを超えたため打ち切りました。');
    if (error?.encoding) fail(502, 'unsupported_encoding', '応答が読めない形式で圧縮されていたため、渡しませんでした。');
    if (error?.timedOut) fail(504, 'timeout', '送り先が20秒以内に応答しませんでした。');
    fail(502, 'unreachable', `${host} に接続できませんでした。`);
  });
}
