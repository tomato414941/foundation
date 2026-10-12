import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';
import { fail, DomainError } from './errors.js';
import { publicAddress, publicUrl } from '../shared/http.js';
import type { Transport, OutboundRequest, OutboundResponse } from '../shared/http.js';
export { publicAddress, publicUrl, responseJson } from '../shared/http.js';
export type { Transport, OutboundRequest, OutboundResponse } from '../shared/http.js';

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
