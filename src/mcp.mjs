// A third door onto the same HTTP API.
//
// Some agents cannot reach an arbitrary URL: the only thing their harness connects them to is an MCP
// server. For those, this endpoint is the first line, and without it Foundation does not exist at all.
// It adds no capability that HTTP does not already have, and it holds no state: a call here is the same
// call the CLI would make, made on the caller's behalf with the caller's own key.
//
// Two tools, because the API is the source of truth and a tool per endpoint would be a second one:
//   foundation_guide  the page every agent reads first
//   foundation_api    any request to the API, with the key attached
//
// Both eras of the protocol are served. 2026-07-28 removed the initialize handshake and carries the
// protocol version and client capabilities in each request's _meta, mirrored into headers; the earlier
// revisions negotiate once and send neither. Clients in the wild are spread across both.
export const LATEST = '2026-07-28';
export const SUPPORTED = [LATEST, '2025-11-25', '2025-06-18', '2025-03-26'];
const STATELESS = new Set([LATEST]);
const META = 'io.modelcontextprotocol/';
const INSTRUCTIONS = 'This MCP interface provides access to the Foundation HTTP API. Call foundation_guide first; it describes the currently available operations and their requirements.';

const TOOLS = [
  {
    name: 'foundation_guide',
    title: 'How to use Foundation',
    description: 'Read this first. Explains what Foundation keeps, how to ask its owner for something, and every endpoint foundation_api can reach.',
    inputSchema: { type: 'object', additionalProperties: false },
  },
  {
    name: 'foundation_api',
    title: 'Call the Foundation API',
    description: 'Make one request to the Foundation HTTP API with this key attached. Paths begin with /v1/. Read foundation_guide for what the paths are.',
    inputSchema: {
      type: 'object',
      properties: {
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], description: 'HTTP method' },
        path: { type: 'string', maxLength: 2048, description: 'Path beginning with /v1/, for example /v1/secrets' },
        body: { description: 'JSON body for anything but GET' },
      },
      required: ['method', 'path'],
      additionalProperties: false,
    },
  },
];

const error = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id === undefined ? {} : { id }), error: { code, message, ...(data ? { data } : {}) } });
const text = value => ({ type: 'text', text: value });

// Header values may arrive base64-wrapped when they cannot be written as plain ASCII.
function headerValue(value) {
  if (typeof value !== 'string') return value;
  const wrapped = value.match(/^=\?base64\?(.*)\?=$/);
  return wrapped ? Buffer.from(wrapped[1], 'base64').toString('utf8') : value;
}

function versionOf(headers, message) {
  const declared = message?.params?._meta?.[META + 'protocolVersion'];
  const header = headers['mcp-protocol-version'];
  // Only the handshake itself names its version in params, and only a client that has no _meta uses it.
  if (message?.method === 'initialize' && declared === undefined) return { version: message.params?.protocolVersion ?? '2025-03-26', declared: false };
  if (declared !== undefined && header !== undefined && declared !== header) return { mismatch: 'MCP-Protocol-Version header does not match _meta.' };
  return { version: declared ?? header ?? '2025-03-26', declared: declared !== undefined };
}

// Everything the transport requires of a modern request, checked before the method runs.
function mirrored(headers, message) {
  if (headers['mcp-method'] === undefined) return 'Mcp-Method header is required.';
  if (headers['mcp-method'] !== message.method) return 'Mcp-Method header does not match the request.';
  const named = { 'tools/call': message.params?.name, 'resources/read': message.params?.uri, 'prompts/get': message.params?.name };
  if (!(message.method in named)) return null;
  if (headers['mcp-name'] === undefined) return 'Mcp-Name header is required.';
  if (headerValue(headers['mcp-name']) !== named[message.method]) return 'Mcp-Name header does not match the request.';
  return null;
}

// One call, made against the API the CLI would call. `call` is given the caller's own authorization.
async function runTool(name, args, { call, guide }) {
  if (name === 'foundation_guide') return { content: [text(guide())] };
  if (name !== 'foundation_api') return null;
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { content: [text('Arguments must be an object with method and path.')], isError: true };
  const { method, path, body } = args;
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return { content: [text('method must be one of GET, POST, PUT, PATCH, DELETE.')], isError: true };
  if (typeof path !== 'string' || !path.startsWith('/v1/') || path.length > 2048 || /[\s\\]/.test(path)) return { content: [text('path must begin with /v1/. See foundation_guide.')], isError: true };
  const result = await call({ method, path, body: method === 'GET' ? undefined : body ?? {} });
  let parsed;
  try { parsed = JSON.parse(result.text); } catch { parsed = undefined; }
  return { content: [text(result.text)], ...(parsed === undefined ? {} : { structuredContent: parsed }), ...(result.ok ? {} : { isError: true }) };
}

// Returns what the endpoint should answer with: a status, and a JSON-RPC body unless the status says none.
export async function respond(message, headers, context) {
  const id = message && typeof message === 'object' && !Array.isArray(message) && message.id !== null ? message.id : undefined;
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
    return { status: 400, body: error(id, -32600, 'Invalid Request: expected a single JSON-RPC 2.0 message.') };
  }
  const { version, declared, mismatch } = versionOf(headers, message);
  if (mismatch) return { status: 400, body: error(id, -32020, mismatch) };
  if (!SUPPORTED.includes(version)) {
    return { status: 400, body: error(id, -32022, 'Unsupported protocol version.', { supported: SUPPORTED, requested: version }) };
  }
  const stateless = STATELESS.has(version);
  // A version that carries its metadata per request must carry all of it, every time.
  if (stateless && message.id !== undefined) {
    const meta = message.params?._meta ?? {};
    if (!declared || meta[META + 'clientCapabilities'] === undefined) {
      return { status: 400, body: error(id, -32602, 'Invalid params: _meta must carry ' + META + 'protocolVersion and ' + META + 'clientCapabilities.') };
    }
    const wrong = mirrored(headers, message);
    if (wrong) return { status: 400, body: error(id, -32020, wrong) };
  }
  if (message.id === undefined) return { status: 202, body: null };  // A notification is accepted and answered with nothing.

  const result = value => ({ status: 200, body: { jsonrpc: '2.0', id, result: { ...(stateless ? { resultType: 'complete' } : {}), ...value, _meta: { [META + 'serverInfo']: context.serverInfo } } } });
  if (message.method === 'initialize') {
    if (stateless) return { status: 404, body: error(id, -32601, 'Method not found: this protocol version has no initialize.') };
    return result({ protocolVersion: version, capabilities: { tools: {} }, serverInfo: context.serverInfo, instructions: INSTRUCTIONS });
  }
  if (message.method === 'ping') return result({});
  if (message.method === 'tools/list') return result({ tools: TOOLS });
  if (message.method === 'tools/call') {
    const called = await runTool(message.params?.name, message.params?.arguments, context);
    if (!called) return { status: 404, body: error(id, -32602, 'Unknown tool: ' + String(message.params?.name)) };
    return result(called);
  }
  return { status: 404, body: error(id, -32601, 'Method not found: ' + message.method) };
}
