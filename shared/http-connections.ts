import type { HttpConnectionSpec, HttpRequestInput, SourceReference } from './contracts.js';
import type { ConnectionState } from './connections.js';
import { publicUrl } from './http.js';
import { fail } from './errors.js';

export function httpSources(request: HttpRequestInput): SourceReference[] {
  return [...(request.connectionId ? [{ id: request.connectionId }] : []),
    ...request.bindings.flatMap(binding => binding.parts.filter((part): part is SourceReference => typeof part !== 'string'))];
}

export function connectionDestination(state: ConnectionState, request: HttpRequestInput, origin: string): string {
  if (!state.method.http) fail(400, 'invalid_http_connection', 'This connection does not provide HTTP authentication.');
  const field = state.method.http.urlField;
  const configured = field && (
    (state.method.kind === 'token' ? state.method.config.constants?.[field] : undefined) ?? state.fields?.[field]
  );
  if (field && !configured) fail(409, 'reconnect_required', 'Reconnect with a destination URL.');
  const url = publicUrl(request.url ?? configured ?? '', origin);
  if (configured && url.origin !== publicUrl(configured, origin).origin)
    fail(400, 'invalid_destination', 'Use this connection only at its configured destination host.');
  return url.href;
}

export function authenticateHttp(url: string, headers: Record<string, string>, spec: HttpConnectionSpec,
  outputs: Record<string, string>): { url: string; headers: Record<string, string>; sensitive: string[] } {
  const target = new URL(url), result = { ...headers }, sensitive: string[] = [];
  if (Object.keys(headers).some(name => ['host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization'].includes(name.toLowerCase())))
    fail(400, 'invalid_authentication', 'Use HTTP headers that do not override routing or transport settings.');
  const output = (name: string, secret = true) => {
    if (!Object.hasOwn(outputs, name)) fail(400, 'invalid_authentication', 'Choose an available authentication output.');
    const value = outputs[name]!;
    if (secret) sensitive.push(value);
    return value;
  };
  const header = (name: string, value: string) => {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
      ['host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization'].includes(name.toLowerCase()) ||
      /[\r\n\0]/.test(value)) fail(400, 'invalid_authentication', 'Use a valid authentication header.');
    if (Object.keys(result).some(key => key.toLowerCase() === name.toLowerCase()))
      fail(400, 'invalid_authentication', 'Let the selected connection supply its authentication header.');
    result[name] = value;
    sensitive.push(value);
  };
  const auth = spec.authentication;
  if (auth.kind === 'bearer') header('Authorization', 'Bearer ' + output(auth.token));
  else if (auth.kind === 'basic') {
    const username = output(auth.username), password = output(auth.password);
    if (username.includes(':')) fail(400, 'invalid_authentication', 'A Basic authentication username cannot contain a colon.');
    const bytes = new TextEncoder().encode(username + ':' + password);
    const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
    header('Authorization', 'Basic ' + encoded);
    sensitive.push(encoded);
  } else if (auth.kind === 'header' || auth.kind === 'query') {
    const name = typeof auth.name === 'string' ? auth.name : output(auth.name.output, false), value = output(auth.value);
    if (auth.kind === 'header') header(name, value);
    else {
      if (!name || /[\r\n\0]/.test(name) || target.searchParams.has(name))
        fail(400, 'invalid_authentication', 'Let the selected connection supply its authentication query parameter.');
      target.searchParams.set(name, value);
    }
  }
  sensitive.push(target.href);
  return { url: target.href, headers: result, sensitive };
}
