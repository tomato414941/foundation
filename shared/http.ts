import ipaddr from 'ipaddr.js';
import { fail } from './errors.js';

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
const globalV6 = ipaddr.IPv6.parseCIDR('2000::/3');
const publicRanges = new Set([
  'unicast', 'amt', 'as112', 'as112v6', 'orchid2', 'droneRemoteIdProtocolEntityTags',
]);
export function publicAddress(address: string): boolean {
  if (!ipaddr.isValid(address) || address.includes('%')) return false;
  const parsed = ipaddr.parse(address);
  return publicRanges.has(parsed.range()) &&
    (!(parsed instanceof ipaddr.IPv6) || parsed.match(globalV6));
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
    (ipaddr.isValid(host) && !publicAddress(host))
  )
    fail(400, 'private_destination', 'Choose a public HTTPS destination.');
  return url;
}
export function responseJson(response: OutboundResponse): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response.body));
  } catch {
    fail(502, 'invalid_response', 'The service returned an invalid response.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(502, 'invalid_response', 'The service returned an invalid response.');
  return value as Record<string, unknown>;
}

export class BrowserTransport implements Transport {
  constructor(readonly origin: string) {}
  async send(input: OutboundRequest): Promise<OutboundResponse> {
    const url = publicUrl(input.url, this.origin), max = input.maxBytes ?? 1_048_576;
    if (input.body && (typeof input.body === 'string' ? new TextEncoder().encode(input.body).length : input.body.length) > max)
      fail(413, 'body_limit', 'The request body is too large.');
    let response: Response;
    try {
      response = await fetch(url, { method: input.method ?? 'GET', headers: input.headers,
        body: typeof input.body === 'string' ? input.body : input.body ? new Uint8Array(input.body) : undefined,
        credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
        signal: AbortSignal.any([AbortSignal.timeout(20_000), ...(input.signal ? [input.signal] : [])]) });
    } catch {
      if (input.signal?.aborted) fail(409, 'cancelled', 'The operation was cancelled.');
      fail(409, 'browser_exchange_unavailable', 'Restart authorization using the CLI on this device.');
    }
    const reader = response.body?.getReader(), chunks: Uint8Array[] = [];
    let length = 0;
    if (reader) try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        length += next.value.length;
        if (length > max) fail(413, 'body_limit', 'The response body is too large.');
        chunks.push(next.value);
      }
    } finally { await reader.cancel(); }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
    return { status: response.status, headers: Object.fromEntries(response.headers), body };
  }
}
