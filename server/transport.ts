import { lookup } from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';
import { request } from 'node:https';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';
import { fail, DomainError } from './errors.js';

export interface OutboundRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  signal?: AbortSignal;
  maxBytes?: number;
}
export interface OutboundResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}
export interface Transport {
  send(input: OutboundRequest): Promise<OutboundResponse>;
}
const blocked = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const)
  blocked.addSubnet(address, prefix, 'ipv4');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
for (const [address, prefix] of [
  ['2001::', 32],
  ['2001:db8::', 32],
  ['2002::', 16],
] as const)
  blocked.addSubnet(address, prefix, 'ipv6');
export function publicAddress(address: string): boolean {
  const family = isIP(address);
  return family === 4
    ? !blocked.check(address, 'ipv4')
    : family === 6 && globalV6.check(address, 'ipv6') && !blocked.check(address, 'ipv6');
}
export function publicUrl(value: string, ownOrigin?: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(400, 'invalid_url', 'Enter an absolute HTTPS URL.');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== '443') ||
    url.origin === ownOrigin
  )
    fail(400, 'invalid_url', 'Choose a public HTTPS destination.');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    (isIP(host) && !publicAddress(host))
  )
    fail(400, 'private_destination', 'Choose a public HTTPS destination.');
  return url;
}
export class PublicTransport implements Transport {
  constructor(readonly origin: string) {}
  async send(input: OutboundRequest): Promise<OutboundResponse> {
    const url = publicUrl(input.url, this.origin),
      host = url.hostname.replace(/^\[|\]$/g, '');
    const max = input.maxBytes ?? 1_048_576;
    if (input.body && Buffer.byteLength(input.body) > max)
      fail(413, 'body_limit', 'The request body is too large.');
    const headers: Record<string, string> = {
      'user-agent': 'Foundation/1.0',
      accept: 'application/json',
      'accept-encoding': 'identity',
    };
    for (const [name, value] of Object.entries(input.headers ?? {})) {
      const key = name.toLowerCase();
      if (
        [
          'host',
          'connection',
          'content-length',
          'transfer-encoding',
          'upgrade',
          'proxy-authorization',
          'proxy-connection',
          'accept-encoding',
          'te',
          'trailer',
        ].includes(key) ||
        !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(key) ||
        /[\r\n\u0000]/.test(value)
      )
        fail(400, 'invalid_header', 'Choose a valid request header.');
      headers[key] = value;
    }
    try {
      const records = await lookup(host, { all: true, verbatim: true });
      if (!records.length || records.some((record) => !publicAddress(record.address)))
        fail(400, 'private_destination', 'Choose a public HTTPS destination.');
      const address = records[0]!;
      const signal = AbortSignal.any([AbortSignal.timeout(20_000), ...(input.signal ? [input.signal] : [])]);
      return await new Promise<OutboundResponse>((resolve, reject) => {
        const options = {
          method: input.method ?? 'GET',
          headers,
          signal,
          agent: false,
          lookup: (
            _hostname: string,
            options: import('node:dns').LookupOptions,
            callback: Parameters<import('node:net').LookupFunction>[2],
          ) => {
            if (options.all) callback(null, [address]);
            else callback(null, address.address, address.family);
          },
        };
        const req = request(url, options, (response) => {
          const chunks: Buffer[] = [];
          let size = 0;
          response.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > max) {
              response.destroy(new DomainError(413, 'body_limit', 'The response body is too large.'));
            } else chunks.push(chunk);
          });
          response.on('error', reject);
          response.on('end', () => {
            try {
              let body = Buffer.concat(chunks);
              const encoding = response.headers['content-encoding'];
              if (encoding && encoding !== 'identity') {
                const decompress =
                  encoding === 'gzip'
                    ? gunzipSync
                    : encoding === 'deflate'
                      ? inflateSync
                      : encoding === 'br'
                        ? brotliDecompressSync
                        : null;
                if (!decompress)
                  throw new DomainError(
                    502,
                    'invalid_response',
                    'The service returned an unsupported response.',
                  );
                body = decompress(body, { maxOutputLength: max });
              }
              const responseHeaders: Record<string, string> = {};
              for (const [key, value] of Object.entries(response.headers))
                if (
                  value !== undefined &&
                  ![
                    'set-cookie',
                    'set-cookie2',
                    'content-encoding',
                    'transfer-encoding',
                    'connection',
                  ].includes(key)
                )
                  responseHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
              resolve({
                status: response.statusCode ?? 502,
                headers: responseHeaders,
                body: new Uint8Array(body),
              });
            } catch (error) {
              reject(error);
            }
          });
        });
        req.on('error', reject);
        req.end(input.body);
      });
    } catch (error) {
      if (error instanceof DomainError) throw error;
      if (input.signal?.aborted) fail(409, 'cancelled', 'The operation was cancelled.');
      fail(502, 'service_unavailable', 'The service could not be reached. Try again.');
    }
  }
}
export function responseJson(response: OutboundResponse): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(response.body).toString('utf8'));
  } catch {
    fail(502, 'invalid_response', 'The service returned an invalid response.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(502, 'invalid_response', 'The service returned an invalid response.');
  return value as Record<string, unknown>;
}
