import Ajv from 'ajv/dist/2020.js';
import { fail } from './errors.mjs';
import { KINDS } from './resources.mjs';

// These declarations are the HTTP contract: the router, JSON reader and OpenAPI all use them.
// Authorization, state transitions and service-specific checks stay with their domain objects.
const string = { type: 'string' }, boolean = { type: 'boolean' }, integer = { type: 'integer' };
const object = (properties = {}, required = []) => ({ type: 'object', properties, ...(required.length ? { required } : {}) });
const array = items => ({ type: 'array', items });
const nullable = schema => ({ anyOf: [schema, { type: 'null' }] });
const choice = values => ({ type: 'string', enum: values });
const errorCode = (schema, code) => ({ ...schema, 'x-error-code': code });
const ref = name => ({ $ref: '#/components/schemas/' + name });
const map = values => ({ type: 'object', additionalProperties: values });
const result = (name, schema) => object({ [name]: schema }, [name]);
const time = { type: 'integer', description: 'Unix time in milliseconds.' };
const iso = { type: 'string', description: 'ISO 8601 timestamp.' };
const resourceName = errorCode({ type: 'string', minLength: 1, description: 'Literal name, 1–200 UTF-16 code units, without control characters. A slash has no special meaning for secrets.' }, 'invalid_name');
const principalId = { type: 'string', pattern: '^[A-Za-z0-9-]{1,64}$' };
const id = { type: 'string', pattern: '^[a-f0-9-]{36}$' };
const pointer = { type: 'string', pattern: '^(?:/(?:[^~/]|~[01])*)*$', description: 'JSON Pointer (RFC 6901), in JSON string form. / selects members; ~0 encodes ~ and ~1 encodes /. No URI fragment prefix.' };
const uriTemplate = { type: 'string', description: 'URI Template (RFC 6570). Every referenced variable must be supplied. Expanded endpoints must use public HTTPS; use {+value} for a complete URL.' };
const sourceReference = (extra = {}) => ({ oneOf: [
  { ...object({ name: resourceName, ...extra }, ['name']), additionalProperties: false },
  { ...object({ id, output: { type: 'string', minLength: 1, maxLength: 200, description: 'Exact connection output name. Not valid for a secret.' }, ...extra }, ['id']), additionalProperties: false },
] });
const requestId = { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' };
const scopes = errorCode({ type: ['array', 'null'], items: errorCode(string, 'invalid_scopes') }, 'invalid_scopes');
const scheme = choice(['oauth', 'role', 'token']);
const app = nullable({ anyOf: [id, { const: 'foundation' }] });
const field = object({ name: resourceName, label: string, site: string, readable: boolean, multiline: boolean, replace: boolean }, ['name', 'label']);
const connect = object({ service: string, auth_scheme: scheme, connection_id: id, scopes, app,
  fields: { ...map(string), description: 'token: the values the service\'s token scheme lists, by field name.' }, name: { ...string, description: 'token: what to call the connection; defaults to the service name followed by のトークン.' } }, ['service']);
const requestProperties = {
  to: errorCode(principalId, 'invalid_principal'), binding_message: errorCode({ type: 'string', maxLength: 240 }, 'invalid_purpose'), steps: errorCode({ type: ['array', 'null'], items: errorCode(string, 'invalid_steps'), maxItems: 20 }, 'invalid_steps'),
  valid_minutes: errorCode({ type: ['integer', 'null'], description: 'Expiry in minutes; default 30, from 1 to 1440. null uses the default.' }, 'invalid_validity'),
};
// One authorization detail (RFC 9396): a type and what that type needs.
const relationDetail = object({ type: { const: 'relation' }, relation: string, object_type: choice(['principal', 'resource']), object_id: string }, ['type', 'relation']);
const detailOf = (type, fields, required = []) => object({ type: { const: type }, ...fields }, ['type', ...required]);
const appValues = { ...object({ service: string, name: resourceName, client_id: string, client_secret: { ...string, writeOnly: true } }),
  description: 'Client fields are top-level keys. Additional service-specific keys (for example runame or domain) are declared by app_fields in GET /v1/services or the service resource. Client secrets are write-only.' };
const lifetime = errorCode(nullable(object({ end: errorCode(nullable(choice(['exit', 'idle'])), 'invalid_lifetime'), idle_seconds: errorCode(nullable(integer), 'invalid_lifetime'), max_seconds: errorCode(nullable(integer), 'invalid_lifetime') })), 'invalid_lifetime');
const command = { command: errorCode({ ...array(string), minItems: 1 }, 'invalid_command'), stdin: errorCode(nullable(string), 'invalid_stdin'), timeout_seconds: errorCode(nullable(integer), 'invalid_timeout') };
const environment = { name: resourceName, size: errorCode(nullable(choice(['small', 'medium', 'large'])), 'invalid_size'), lifetime, identity: errorCode(nullable(principalId), 'invalid_principal') };
const oauthFields = array(object({ name: string, label: string, required: boolean, placeholder: string, note: string, pattern: string, leading: boolean }, ['name', 'label']));
const tokenFields = array(object({ name: string, label: string, required: boolean, placeholder: string, note: string, pattern: string, secret: boolean }, ['name', 'label']));
const resourceBase = { id: string, kind: choice(KINDS), name: string, holder_id: principalId, created_at: iso, updated_at: iso, lines: array(object({ subject_id: principalId, relation: string, created_at: iso }, ['subject_id', 'relation', 'created_at'])) };
const resource = (kind, fields) => object({ ...resourceBase, kind: { const: kind }, ...fields }, ['id', 'kind', 'name']);

export const schemas = {
  Error: object({ error: object({ code: string, message: string }, ['code', 'message']) }, ['error']),
  Ok: object({ ok: { const: true } }, ['ok']),
  Empty: object(),
  Login: object({ email: errorCode(string, 'invalid_email'), return_to: errorCode(string, 'invalid_return') }, ['email']),
  VerifyLogin: object({ email: errorCode(string, 'invalid_email'), token_hash: errorCode(string, 'invalid_link'), return_to: errorCode(string, 'invalid_return') }, ['email', 'token_hash']),
  PendingLogin: object({ email: string, expires_at: time, resend_at: time }, ['email', 'expires_at', 'resend_at']),
  CreatePrincipal: object({ name: string, alias: string, actor: boolean, key: boolean }),
  Rename: object({ name: resourceName }, ['name']),
  Principal: object({ id: principalId, name: string, created_at: iso, alias: nullable(string),
    keys: array(ref('Key')), acts_for: array(principalId), owners: array(principalId) }, ['id', 'name', 'created_at']),
  Key: object({ id, kind: { const: 'key' }, created_at: iso, last_used_at: nullable(iso), environment: nullable(id), environment_id: id, expires_at: time }, ['id']),
  Me: object({ principal: ref('Principal'), key: ref('Key'), acts_for: array(principalId), owners: array(principalId),
    keys: array(ref('Key')), requests: array(ref('Request')) }, ['principal', 'acts_for', 'owners', 'keys', 'requests']),
  Relation: object({ subject_id: principalId, relation: string, object_type: choice(['principal', 'resource']), object_id: string, created_at: iso }, ['relation', 'object_type', 'object_id']),
  RelationInput: object({ subject: principalId, relation: string, object_type: choice(['principal', 'resource']), object_id: string }, ['relation', 'object_type', 'object_id']),
  AuthorizationDetail: { anyOf: [relationDetail,
    detailOf('secret', { fields: { anyOf: [field, { ...array(field), minItems: 1, maxItems: 8 }] } }, ['fields']),
    detailOf('connection', connect.properties, ['service']),
    detailOf('app', { service: string, name: resourceName }, ['service'])] },
  CreateRequest: errorCode(object({ ...requestProperties, authorization_details: errorCode({ ...array(ref('AuthorizationDetail')), minItems: 1, maxItems: 1 }, 'invalid_authorization_details') }, ['authorization_details']), 'invalid_authorization_details'),
  Request: object({ id: requestId, authorization_details: array(ref('AuthorizationDetail')), from: principalId, to: nullable(principalId),
    binding_message: string, steps: array(string), status: choice(['pending', 'granted', 'denied', 'cancelled']), created_at: time, expires_at: time, expires_in: integer, interval: integer,
    verification_uri: string, requester_name: string, user_code: string, reason: string,
    result: object({ names: array(string), replaced: array(string), relation: string, object_type: string, object_id: string, connection_id: id, app_id: id }),
    events: array(object({ event: string, at: time, detail: object() })), service: ref('ServiceDescription'),
    connection: nullable(ref('Connection')), auth_scheme: scheme, app: nullable(object({ id: string, name: string, foundation: boolean })), store: array(field),
  }, ['id', 'authorization_details', 'from', 'to', 'status', 'verification_uri', 'expires_at', 'interval']),
  GrantRequest: { anyOf: [
    object({ entries: array(object({ name: resourceName, content: string }, ['name', 'content'])) }, ['entries']),
    object({ user_code: string }), appValues,
  ], description: 'secret: entries in the requested field order; relation: the user_code the asker showed, when the request was addressed to nobody; app: name, client_id, client_secret and service-specific top-level app fields. connection is granted through /v1/connections and the service consent flow. Wrong user codes, including missing ones, count toward the attempt limit.' },
  Settings: object({ principal_id: principalId, return_url: string, refresh_url: string, webhook_url: nullable(string),
    notifies: boolean, webhook_secret: string, created_at: iso }, ['principal_id', 'return_url', 'refresh_url', 'notifies']),
  SettingsInput: object({ return_url: string, refresh_url: string, webhook_url: string }, ['return_url']),
  Compute: object({ month: string, used_seconds: integer, limit_seconds: integer }, ['month', 'used_seconds', 'limit_seconds']),
  ServiceSummary: object({ id: string, name: string, logo: string, catalog: boolean, removed: boolean }, ['id', 'name', 'catalog']),
  ServiceDescription: object({ id: string, name: string, api: string, docs: string, console: string, logo: string, catalog: boolean,
    auth_schemes: object({ oauth: object({ available: boolean, variables: array(string), hint: string, takes_apps: boolean, foundation_app: boolean,
      app_fields: oauthFields, scopes: nullable(object({ base: scopes, documentation_url: string })), can_revoke: boolean, can_reconnect: boolean }),
    role: object({ available: boolean, variables: array(string), hint: string, fields: oauthFields, instructions: string }),
    token: object({ available: boolean, variables: array(string), hint: string, fields: tokenFields, instructions: string, console: nullable(string) }) }) }, ['id', 'name', 'auth_schemes']),
  OAuthDefinition: object({ authorize: uriTemplate, token: uriTemplate,
    injection: { ...map(pointer), description: 'Environment variable names mapped to JSON Pointers selecting /access_token, /account, /expires_at or a declared app/kept field. Missing, null or empty optional values are omitted.' }, authorize_params: map(string),
    scope_separator: choice([' ', ',', '+']), pkce: boolean, client_auth: choice(['basic', 'body']), token_format: choice(['form', 'json']),
    ok_field: pointer, keep: array(string), subject_prefix: string, defaults: map(string), app_fields: oauthFields,
    identity: object({ url: uriTemplate, method: choice(['GET', 'POST']), headers: map(string), json: {}, token_header: string,
      id: { anyOf: [pointer, array(pointer)] }, label: { anyOf: [pointer, array(pointer)] }, optional: boolean,
      from: choice(['token', 'app']), ok_field: pointer }),
    revoke: object({ url: uriTemplate, style: choice(['rfc7009', 'bearer', 'delete']), auth: { const: 'none' } }, ['url', 'style']),
    scopes: object({ base: scopes, docs: string }, ['base']), hint: string,
  }, ['authorize', 'token', 'injection']),
  TokenDefinition: object({ fields: tokenFields, console: string, instructions: { ...string, description: 'What to do at the service before pasting, for the person connecting.' },
    injection: { ...map(pointer), description: 'Environment variable names mapped to JSON Pointers selecting a declared field.' }, hint: string }, ['fields', 'injection']),
  ServiceDefinition: { ...object({ name: string, api: string, docs: string, console: string,
    auth_schemes: { ...object({ oauth: ref('OAuthDefinition'), token: ref('TokenDefinition') }), additionalProperties: false } }, ['name']),
    additionalProperties: false, description: 'A holder-defined service. auth_schemes may be empty; catalog adapters and role schemes cannot be registered here. URLs use RFC 6570; response selectors and injection values use RFC 6901 JSON Pointers. Endpoint variables come from declared app fields/client_id; identity URLs may also use access_token and kept fields, and revocation URLs access_token/refresh_token.' },
  AppInput: appValues,
  Secret: resource('secret', { size: integer }),
  Object: resource('object', { size: integer, type: nullable(string) }),
  Connection: resource('connection', { service: ref('ServiceSummary'), auth_scheme: scheme, status: string, label: string,
    facts: object(), variables: array(string), app: nullable(object({ id: string, name: string, foundation: boolean })), subject: nullable(string),
    generation: integer, expires_at: nullable(time), can_reconnect: boolean, can_revoke: boolean, available: boolean }),
  App: resource('app', { service: ref('ServiceSummary'), foundation: boolean, client_id: string, settings: map(string), connections: integer }),
  Service: resource('service', { definition: object(), service: ref('ServiceDescription'), dependents: integer }),
  Environment: resource('environment', { size: string, lifetime, identity: nullable(principalId), status: string,
    started_at: nullable(iso), last_active_at: nullable(iso), expires_at: nullable(iso) }),
  Resource: { oneOf: ['Secret', 'Object', 'Connection', 'App', 'Service', 'Environment'].map(ref) },
  PatchResource: { ...object({ name: resourceName, auth_schemes: object({ oauth: ref('OAuthDefinition') }), client_id: string, client_secret: string }), description: 'Apps also accept their service-specific top-level client fields, as declared by app_fields.' },
  DeleteResource: object({ revoke: boolean, confirm: boolean }),
  Connect: { ...object({ ...connect.properties, request_id: requestId }), description: 'With request_id the stored request determines service, scheme, app and scopes. Otherwise service is required. oauth and role need a browser session and return where to go next. token connects at once with the given fields; with connection_id it replaces that connection\'s values. Use a connection detail at POST /v1/requests to ask a person to connect.' },
  ConnectResult: object({ url: string, state: string, connection: ref('Connection') }),
  Confirmation: object({ connection: ref('Connection'), changes: array(object()) }, ['connection', 'changes']),
  CreateEnvironment: object(environment),
  Run: object({ ...environment, ...command }, ['command']),
  CommandInput: object(command, ['command']),
  Command: object({ id, environment_id: id, command: array(string), status: choice(['running', 'done', 'timed_out', 'failed']),
    exit_code: nullable(integer), stdout: nullable(string), stderr: nullable(string), started_at: iso, ended_at: nullable(iso) }, ['id', 'environment_id', 'command', 'status', 'stdout', 'stderr']),
  SourceReference: { ...sourceReference(), description: 'Exactly one of a literal secret name or a resource id. A single connection value also requires output. Names and IDs are never inferred from each other.' },
  InjectionInput: sourceReference({ as: errorCode(nullable(string), 'invalid_env'), filename: errorCode(nullable(string), 'invalid_filename') }),
  Inject: object({ names: { ...array(ref('InjectionInput')), minItems: 1, maxItems: 16 } }, ['names']),
  Injection: object({ injection: object({ environment: map(string), files: array(object({ env: string, filename: string, content: string, encoding: { const: 'base64' } }, ['env', 'filename', 'content', 'encoding'])) }, ['environment', 'files']),
    expires_at: nullable(time), expires_in: nullable(integer) }, ['injection', 'expires_at', 'expires_in']),
  FetchBinding: { ...object({ target: pointer, parts: { ...array({ anyOf: [string, ref('SourceReference')] }), minItems: 1, maxItems: 32 } }, ['target', 'parts']), additionalProperties: false,
    description: 'Replace an existing string at target by concatenating literal strings and referenced values once. Targets are header values, utf8 body, JSON string values or form fields. Targets must be unique. URLs cannot be bound.' },
  FetchInput: { ...object({ url: string, method: string, headers: nullable(map(string)), body: string, body_encoding: choice(['utf8', 'base64']),
    json: {}, form: map(string), bindings: { ...array(ref('FetchBinding')), maxItems: 32 }, save: resourceName }, ['url']), additionalProperties: false,
    description: 'body, json and form are mutually exclusive. All strings are literal. Bindings are applied before JSON/form encoding. Up to eight distinct source references; connections require output. Authorization and public-HTTPS destination checks apply before sending.' },
  FetchResult: object({ response: object({ status: integer, headers: map(string), body: string, body_encoding: choice(['utf8', 'base64']) }, ['status', 'headers']), saved: array(object({ id, name: string })) }, ['response']),
  Function: object({ id: string, description: string, endpoint: string, input: map(string), output: string, save: string }, ['id', 'endpoint', 'description']),
  Usage: object({ secrets: ref('StorageUsage'), objects: nullable(ref('StorageUsage')) }, ['secrets', 'objects']),
  StorageUsage: object({ count: integer, bytes: integer, count_max: integer, bytes_max: integer }, ['count', 'bytes', 'count_max', 'bytes_max']),
  AuditEntry: object({ id, actor_id: string, action: string, object_type: string, object_id: string, detail: object(), at: iso }, ['id', 'actor_id', 'action', 'object_type', 'object_id', 'detail', 'at']),
  Overview: object({ user: object({ id: principalId, email: nullable(string) }, ['id', 'email']), principal: ref('Principal'),
    secrets: array(ref('Secret')), connections: array(ref('Connection')), apps: array(ref('App')), services: array(ref('Service')),
    catalog: array(ref('ServiceDescription')), principals: array(ref('Principal')), actors: array(ref('Principal')), requests: array(ref('Request')),
    functions: array(ref('Function')), settings: nullable(ref('Settings')), environments: array(ref('Environment')), compute: ref('Compute') },
    ['user', 'principal', 'secrets', 'connections', 'apps', 'services', 'catalog', 'principals', 'actors', 'requests', 'functions', 'settings', 'environments', 'compute']),
  Export: object({ exported_at: iso, owner: nullable(string), origin: string,
    secrets: array({ allOf: [ref('Secret'), object({ content: string, encoding: { const: 'base64' } }, ['content', 'encoding'])] }),
    connections: array({ allOf: [ref('Connection'), object({ fields: map(string) })] }), services: array(object({ id, name: string, definition: object() })), principals: array(ref('Principal')) }, ['exported_at', 'owner', 'origin', 'secrets', 'connections', 'services', 'principals']),
};

const query = (name, schema = string, description, required = false) => ({ name, in: 'query', schema, required, ...(description ? { description } : {}) });
const header = (name, description) => ({ name, in: 'header', schema: string, description });
const json = schema => ({ 'application/json': { schema: typeof schema === 'string' ? ref(schema) : schema } });
const response = (schema, description = 'Success') => ({ description, content: json(schema) });
const body = schema => ({ required: true, content: json(schema) });
const secure = [{ bearer: [] }, { session: [] }], session = [{ session: [] }];
const as = query('as', principalId, 'Principal whose resources to use. Defaults to the caller. Requires an actor relation or the relevant resource permission. CLI/MCP select it automatically only when acts_for has exactly one entry.');
function op(operationId, summary, output, { input, status = 200, description, parameters = [], security = secure, ...rest } = {}) {
  return { operationId, summary, ...(description ? { description } : {}), security, parameters,
    ...(input ? { requestBody: body(input) } : {}), responses: { [status]: response(output), default: response('Error', 'Failure. error.code is stable; error.message is display text. State-dependent failures may include additional fields.') }, ...rest };
}
const okay = (name, summary, extra = {}) => op(name, summary, 'Ok', { input: 'Empty', ...extra });
const one = type => result(type.toLowerCase(), ref(type));
const many = (key, type) => result(key, array(ref(type)));
const state = object({ state: string }, ['state']);
const rawContent = { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } }, '*/*': { schema: { type: 'string', format: 'binary' } } };
const etag = { ETag: { description: 'Opaque secret revision. Return it as If-Match to protect against overwrites.', schema: string } };

// Route names are internal dispatch identifiers, not another copy of URL patterns in the handler.
export const routes = [
  { name: 'health', path: '/health', methods: { get: op('health', 'Check server health', object({ status: { const: 'ok' } }, ['status']), { security: [] }) } },
  { name: 'login', path: '/v1/login', methods: {
    get: op('getLogin', 'Read sign-in availability and pending email', object({ available: boolean, method: { const: 'email_link' }, pending: nullable(ref('PendingLogin')) }, ['available', 'method', 'pending']), { security: [] }),
    post: op('sendLoginLink', 'Send an email sign-in link', result('pending', ref('PendingLogin')), { input: 'Login', status: 202, security: [], 'x-input-error': 'invalid_email' }),
    delete: okay('cancelLogin', 'Cancel pending email sign-in', { requestBody: undefined, security: [] }),
  } },
  { name: 'verifyLogin', path: '/v1/login/verify', methods: { post: op('verifyLogin', 'Redeem an email sign-in link', object({ ok: { const: true }, return_to: string }, ['ok', 'return_to']), { input: 'VerifyLogin', security: [], 'x-input-error': 'invalid_link', description: 'Requires a same-origin browser request, but not the browser that sent the email. Sets an HttpOnly fdn_session cookie.' }) } },
  { name: 'session', path: '/v1/session', methods: { delete: op('logout', 'End this browser session', object({ ok: { const: true }, authLogout: boolean }, ['ok', 'authLogout']), { security: [] }) } },
  { name: 'catalog', path: '/v1/services', methods: { get: op('listCatalog', 'List built-in services and connection methods', many('services', 'ServiceDescription'), { security: [] }) } },
  { name: 'return', path: '/v1/requests/{requestId}/return', methods: { get: op('getRequestReturn', 'Read the return destination for a request', result('back', object({ name: string, return_url: string, refresh_url: string }, ['name', 'return_url', 'refresh_url'])), { security: [] }) } },
  { name: 'exchangeLink', path: '/v1/links/exchange', methods: { post: okay('exchangeLink', 'Exchange a one-use request link for a request-scoped cookie', { input: object({ link: string, request_id: requestId }, ['link', 'request_id']), security: [], 'x-input-error': 'invalid_link' }) } },
  { name: 'me', path: '/v1/principals/me', methods: {
    get: op('getMe', 'Read the caller and its current access', 'Me'), patch: op('renameMe', 'Rename the caller', one('Principal'), { input: 'Rename', 'x-input-error': 'invalid_name' }),
    delete: okay('removeMe', 'Remove the caller and its resources'),
  } },
  { name: 'principals', path: '/v1/principals', methods: {
    get: op('listPrincipals', 'List principals owned by the caller', many('principals', 'Principal')),
    post: op('createPrincipal', 'Create a principal', object({ principal: ref('Principal'), token: string, key: ref('Key') }, ['principal']), {
      input: 'CreatePrincipal', status: 201, security: [{}, ...secure], 'x-input-error': 'invalid_name',
      description: 'Without authentication, name is required and a private Bearer token is issued once. Store it privately; it has no access to anyone else. To ask an owner for access, use it to POST /v1/requests with {"authorization_details":[{"type":"relation","relation":"actor"}]} and give the owner the returned verification_uri and user_code. Only the owner approves; GET /v1/principals/me reports acts_for afterward. With authentication, creates an owned principal; alias is an idempotent local name, actor:true gives it access to the caller, key:true issues a token. The CLI can perform the bootstrap: foundation connect <server> --name <name>.' }),
  } },
  { name: 'principal', group: 'principals', path: '/v1/principals/{principalId}', methods: {
    get: op('getPrincipal', 'Read a principal', one('Principal')), patch: op('renamePrincipal', 'Rename a principal', one('Principal'), { input: 'Rename', 'x-input-error': 'invalid_name' }), delete: okay('removePrincipal', 'Remove an owned principal and its resources'),
  } },
  { name: 'keys', group: 'principals', path: '/v1/principals/{principalId}/keys', methods: {
    get: op('listKeys', 'List a principal’s keys', many('keys', 'Key')),
    post: op('issueKey', 'Issue a key, optionally replacing an existing key', object({ key: ref('Key'), token: string }, ['key', 'token']), { input: object({ replaces: string }), status: 201, description: 'The token is returned only once. Keep it in private storage, not chat or logs.' }),
  } },
  { name: 'key', group: 'principals', path: '/v1/principals/{principalId}/keys/{keyId}', methods: { delete: okay('revokeKey', 'Revoke a key') } },
  { name: 'links', group: 'principals', path: '/v1/principals/{principalId}/links', methods: { post: op('issueLink', 'Issue a one-use link for a store request', object({ link: object({ id, request_id: requestId, expires_at: time }, ['id', 'request_id', 'expires_at']), url: string, expires_at: time }, ['link', 'url', 'expires_at']), { input: object({ request_id: string }, ['request_id']), status: 201, 'x-input-error': 'invalid_request' }) } },
  { name: 'access', group: 'principals', path: '/v1/principals/{principalId}/access', methods: { delete: okay('revokeAccess', 'Revoke a principal’s access to the holder', { parameters: [as] }) } },
  { name: 'compute', group: 'principals', path: '/v1/principals/{principalId}/compute', methods: {
    get: op('getCompute', 'Read monthly compute usage and allowance', one('Compute')),
    put: op('setCompute', 'Set a principal’s monthly compute allowance', one('Compute'), { input: object({ monthly_seconds: integer }, ['monthly_seconds']), 'x-input-error': 'invalid_limit' }),
  } },
  { name: 'settings', group: 'principals', path: '/v1/principals/{principalId}/settings', methods: {
    get: op('getSettings', 'Read return and webhook settings', result('settings', nullable(ref('Settings')))),
    put: op('putSettings', 'Replace return and webhook settings', result('settings', ref('Settings')), { input: 'SettingsInput', 'x-input-error': 'invalid_return_url', description: 'A webhook_secret, when created, is returned once. Events use Foundation-Signature: t=<seconds>,v1=<HMAC-SHA256 of t + "." + raw body>. Verify the signature and timestamp before processing.' }),
    delete: okay('removeSettings', 'Remove return and webhook settings'),
  } },
  { name: 'requests', group: 'requests', path: '/v1/requests', methods: {
    get: op('listRequests', 'List sent or received requests', many('requests', 'Request'), { parameters: [query('status', choice(['pending', 'granted', 'denied', 'cancelled'])), query('to', string, 'Use me for received requests; otherwise lists sent requests.')] }),
    post: op('createRequest', 'Ask someone for a relation, secrets, a connected service or a registered app', one('Request'), { input: 'CreateRequest', status: 201, parameters: [as], 'x-input-error': 'invalid_authorization_details', description: 'authorization_details holds one detail (RFC 9396). A relation with no object, asked of nobody, is how a principal nobody knows asks to act for whoever answers; it returns a user_code to show beside verification_uri (as in RFC 8628). Otherwise the request goes to to, the holder of the object, or the holder selected by as, who answers where they are (as in CIBA); binding_message tells them why. Poll GET /v1/requests/{requestId} no more often than interval seconds; faster polling is answered with slow_down, and an expired request with expired_token. Do not collect secrets in chat.' }),
  } },
  { name: 'request', group: 'requests', path: '/v1/requests/{requestId}', methods: {
    get: op('getRequest', 'Read a request and its outcome', one('Request'), { security: [...secure, { requestLink: [] }] }),
    delete: op('cancelRequest', 'Cancel a sent request', one('Request'), { input: 'Empty' }),
  } },
  { name: 'grant', group: 'requests', path: '/v1/requests/{requestId}/grant', methods: { post: op('grantRequest', 'Grant a request as the one asked', { anyOf: [one('Request'), object({ stored: { const: true }, names: array(string), replaced: array(string) }, ['stored', 'names', 'replaced']), object({ registered: { const: true }, app_id: id }, ['registered', 'app_id'])] }, { input: 'GrantRequest', security: [...secure, { requestLink: [] }], description: 'Request-link cookies may answer only their own request. App registration requires a browser session. A relation is drawn only where the one granting may draw it. Wrong user codes count toward the attempt limit.' }) } },
  { name: 'deny', group: 'requests', path: '/v1/requests/{requestId}/deny', methods: { post: op('denyRequest', 'Decline a received request', one('Request'), { input: 'Empty', security: [...secure, { requestLink: [] }] }) } },
  { name: 'relations', path: '/v1/relations', methods: {
    get: op('listRelations', 'List the caller’s relations', many('relations', 'Relation')),
    post: okay('addRelation', 'Grant a role or action on a principal or resource', { input: 'RelationInput', status: 201, 'x-input-error': 'invalid_relation', description: 'subject defaults to the caller. Roles include actor on principals and viewer/editor on resources. Specific actions may also be granted. The caller must be able to share the target and exercise everything the new relation grants. Ownership is not granted through this endpoint.' }),
    delete: okay('removeRelation', 'Remove or give up a relation', { input: 'RelationInput', 'x-input-error': 'invalid_relation' }),
  } },
  { name: 'environments', path: '/v1/environments', methods: {
    get: op('listEnvironments', 'List execution environments', many('environments', 'Environment'), { parameters: [as] }),
    post: op('createEnvironment', 'Open an execution environment', one('Environment'), { input: 'CreateEnvironment', status: 201, parameters: [as], description: 'Requires a configured runner and available compute allowance. identity is an optional principal the environment may act as; granting it requires pass permission.' }),
  } },
  { name: 'runs', path: '/v1/runs', methods: { post: op('run', 'Open an environment and run one command', object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command']), { input: 'Run', parameters: [as], 'x-input-error': 'invalid_command', description: 'Closes the environment when the command exits. Waits up to 20 seconds; a running command returns 202 and can be polled by its id.', responses: { 200: response(object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command'])), 202: response(object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command'])), default: response('Error', 'Failure') } }) } },
  { name: 'environment', group: 'environments', path: '/v1/environments/{resourceId}', methods: {
    get: op('getEnvironment', 'Read an execution environment', one('Environment')),
    patch: op('setEnvironmentIdentity', 'Attach or detach an environment identity', one('Environment'), { input: object({ identity: nullable(principalId) }, ['identity']), 'x-input-error': 'invalid_identity' }),
    delete: okay('removeEnvironment', 'Close and remove an execution environment'),
  } },
  { name: 'commands', group: 'environments', path: '/v1/environments/{resourceId}/commands', methods: { post: op('startCommand', 'Run a command in an environment', one('Command'), { input: 'CommandInput', 'x-input-error': 'invalid_command', responses: { 200: response(one('Command')), 202: response(one('Command'), 'Still running after 20 seconds; poll by command id.'), default: response('Error', 'Failure') } }) } },
  { name: 'command', group: 'environments', path: '/v1/environments/{resourceId}/commands/{commandId}', methods: { get: op('getCommand', 'Read command status and output', one('Command')) } },
  { name: 'resources', path: '/v1/resources', methods: {
    get: op('listResources', 'List resources or find one by literal name', { anyOf: [many('resources', 'Resource'), one('Resource')] }, {
      parameters: [as, query('kind', choice(KINDS)), query('name', string, 'Exact name lookup for secret, object, service or app; returns resource (singular).'), query('prefix', string), query('service', string, 'Filter connections by service id.'), query('shown', string, 'me lists resources shared with the caller.')],
      description: 'Connection metadata contains no renewable state or token. Apps may include the built-in Foundation app. Without name the result is resources (an array).' }),
    put: op('putResource', 'Create or replace a resource by kind and name', one('Resource'), { parameters: [as, query('kind', choice(['secret', 'object', 'app', 'service']), undefined, true), query('name', resourceName, undefined, true), header('If-Match', 'Secret revision from ETag; mismatch returns 412 secret_changed.'), header('If-None-Match', 'Use * to create a service only when its name is unused; otherwise 412 name_taken.')],
      description: 'kind determines the body: secret/object store raw bytes (including when Content-Type is application/json); app/service parse JSON. Secrets require 1 byte–1 MiB; objects allow up to 25 MiB and preserve Content-Type. Managed connections are created through /v1/connections, not here.',
      requestBody: { required: true, content: { ...rawContent, 'application/json': { schema: { anyOf: [ref('ServiceDefinition'), ref('AppInput'), {}], description: 'ServiceDefinition for kind=service; AppInput for kind=app; arbitrary raw JSON bytes for secret/object.' } } } },
      responses: { 200: { ...response(one('Resource')), headers: etag }, default: response('Error', 'Failure') },
    }),
  } },
  { name: 'resource', group: 'resources', path: '/v1/resources/{resourceId}', methods: {
    get: op('getResource', 'Read resource metadata', one('Resource')),
    put: op('replaceService', 'Replace a service definition', one('Resource'), { input: 'ServiceDefinition', 'x-input-error': 'invalid_definition' }),
    patch: op('patchResource', 'Rename a resource or update an app or service', one('Resource'), { input: 'PatchResource', description: 'For secret/object/connection, supply name. For an app, top-level client fields may also be changed. For a service, name renames the resource and auth_schemes adds connection methods; only those two fields are accepted.' }),
    delete: op('removeResource', 'Remove a resource or disconnect a connection', object({ ok: { const: true }, service_revoked: nullable(boolean), connections_stopped: integer }, ['ok']), { input: 'DeleteResource', description: 'For connections, revoke (boolean) is required: true also attempts service-side revocation. service_revoked is true/false when attempted, null otherwise. For an app in use, confirm:true is required; its connections stop working. Other kinds accept {}. Environments are closed before removal.' }),
  } },
  { name: 'content', group: 'resources', path: '/v1/resources/{resourceId}/content', methods: {
    get: op('getContent', 'Download secret or object bytes', 'Empty', { responses: { 200: { description: 'Secret bytes (application/octet-stream) or object bytes (stored Content-Type).', content: rawContent, headers: etag }, default: response('Error', 'Failure') } }),
    put: op('putContent', 'Replace secret or object bytes', one('Resource'), { requestBody: { required: true, content: rawContent }, parameters: [header('If-Match', 'Expected secret revision from ETag.')], responses: { 200: { ...response(one('Resource')), headers: etag }, default: response('Error', 'Failure') } }),
  } },
  { name: 'objectLink', group: 'resources', path: '/v1/resources/{resourceId}/link', methods: { post: op('createObjectLink', 'Create a time-limited object download URL', object({ id, name: string, url: string, url_expires_at: time }, ['id', 'name', 'url', 'url_expires_at']), { input: object({ minutes: integer }), 'x-input-error': 'invalid_minutes' }) } },
  { name: 'confirmation', path: '/v1/connections/confirmation', methods: {
    get: op('getConfirmation', 'Review changed service authorization', 'Confirmation', { parameters: [as, query('state', string, undefined, true)], security: session }),
    post: op('acceptConfirmation', 'Accept changed service authorization', one('Connection'), { input: state, security: session, parameters: [as], 'x-input-error': 'invalid_state' }),
    delete: okay('cancelConfirmation', 'Cancel changed service authorization', { input: state, security: session, parameters: [as], 'x-input-error': 'invalid_state' }),
  } },
  { name: 'connections', path: '/v1/connections', methods: { post: op('connectService', 'Connect a service', 'ConnectResult', { input: 'Connect', parameters: [as], responses: { 200: response('ConnectResult'), 201: response(one('Connection'), 'A token connection was made.'), default: response('Error', 'Failure') } }) } },
  { name: 'completeConnection', path: '/v1/connections/complete', methods: { post: op('completeRole', 'Finish role-based service authorization', one('Connection'), { input: object({ state: string, fields: map(string) }, ['state']), security: session, parameters: [as], 'x-input-error': 'invalid_state' }) } },
  { name: 'oauthCallback', path: '/oauth/callback', methods: { get: op('oauthCallback', 'Return from service OAuth consent', 'Empty', { security: session, parameters: [query('state', string, undefined, true), query('code'), query('error')], responses: { 303: { description: 'Returns to the service page or original request, with a result code.', headers: { Location: { schema: string } } } } }) } },
  { name: 'injections', path: '/v1/injections', methods: { post: op('inject', 'Obtain secret bytes or current service connections for a process', 'Injection', { input: 'Inject', parameters: [as], 'x-input-error': 'invalid_names', description: 'Each input has exactly one of name (literal secret name) or id (secret/connection id). A secret requires as (a non-reserved environment variable). A connection without output delivers all its named values; output selects one. as can rename a single value. filename delivers base64 file bytes instead of environment text. Connections refresh if needed. Deliver values privately to the intended process; do not print them into chat or logs. CLI exec does this without exposing values to the agent.' }) } },
  { name: 'functions', path: '/v1/functions', methods: { get: op('listFunctions', 'List built-in operations', many('functions', 'Function'), { parameters: [as] }) } },
  { name: 'httpRequest', path: '/v1/functions/http.request', methods: { post: op('httpRequest', 'Send an HTTPS request using saved values', 'FetchResult', { input: 'FetchInput', parameters: [as], description: 'Use bindings to place referenced values at JSON Pointer targets in headers or body. Ordinary strings are literal. json and form are encoded after binding; body is raw text or base64. URLs cannot be binding targets. Public HTTPS only, redirects are returned without following, request/response body limit 1 MiB. Bound values are redacted from the response. save stores the response body as a secret under that name and omits it from the response.' }) } },
  { name: 'usage', path: '/v1/usage', methods: { get: op('getUsage', 'Read storage usage and limits', 'Usage', { parameters: [as] }) } },
  { name: 'audit', path: '/v1/audit-log', methods: { get: op('getAuditLog', 'Read the caller’s audit records', many('entries', 'AuditEntry')) } },
  { name: 'overview', path: '/v1/overview', methods: { get: op('getOverview', 'Read the holder’s workspace', 'Overview', { parameters: [as] }) } },
  { name: 'export', path: '/v1/export', methods: { get: op('exportData', 'Download the holder’s data, including secret bytes', 'Export', { parameters: [as], description: 'Contains base64 secret content. Handle as private data. Managed connections export metadata, not renewable state.' }) } },
];

const pathSchemas = { principalId, requestId, resourceId: id, keyId: id, commandId: id };
const compiled = routes.map(route => {
  const names = [...route.path.matchAll(/\{(\w+)\}/g)].map(match => match[1]);
  const pattern = route.path.split(/(\{\w+\})/).map(part => part.startsWith('{')
    ? '(' + pathSchemas[part.slice(1, -1)].pattern.slice(1, -1) + ')' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('');
  return { ...route, names, pattern: new RegExp('^' + pattern + '$') };
});
export function matchRoute(path, method) {
  for (const route of compiled) {
    const match = path.match(route.pattern);
    if (match) return { ...route, params: Object.fromEntries(route.names.map((name, at) => [name, match[at + 1]])), operation: route.methods[method.toLowerCase()] };
  }
  return null;
}

const ajv = new Ajv({ strict: false, allErrors: true, verbose: true, validateFormats: false });
const contract = { components: { schemas } };
ajv.addSchema(contract, 'foundation-api');
const validators = new Map();
export function validateSchema(schema, value) {
  const shape = typeof schema === 'string' ? ref(schema) : schema;
  const key = JSON.stringify(shape);
  if (!validators.has(key)) validators.set(key, ajv.compile({ ...contract, ...shape }));
  const check = validators.get(key);
  return { valid: check(value), errors: check.errors ?? [] };
}
export function validateBody(route, value, variant) {
  // Raw secret/object uploads bypass JSON reading even when their media type is JSON.
  const selected = route?.name === 'resources' ? (variant === 'service' ? 'ServiceDefinition' : variant === 'app' ? 'AppInput' : null)
    : route?.operation?.requestBody?.content?.['application/json']?.schema;
  if (!selected) return;
  const checked = validateSchema(selected, value);
  if (!checked.valid) {
    const code = checked.errors.find(error => error.parentSchema?.['x-error-code'])?.parentSchema['x-error-code'];
    fail(400, code || route.operation?.['x-input-error'] || 'invalid_input', '入力内容を確認してください。');
  }
}

export function openapi(origin, version) {
  return {
    openapi: '3.1.1',
    info: { title: 'Foundation API', version,
      description: 'Store and share resources, authorize services and run operations. HTTP is the common interface for the web UI, CLI and MCP. Public specification: /openapi.json. Browser reference: /docs.\n\nUse Authorization: Bearer <key> for programs; fdn_session for a signed-in browser. Bearer takes precedence over cookies. Cookie-authenticated writes require the same Origin; cross-site calls are rejected. Keys obtain access through relations, not by being issued. The service authorization endpoints explicitly require a browser session.\n\nJSON writes use Content-Type: application/json and an object body, including {} where indicated. Most JSON bodies are limited to 12,000 bytes; store request completion, raw uploads, commands and http.request have their documented larger limits. Names are literal, URL-encoded query values. Failures use {error:{code,message,...}}; 401 authentication, 403 permission/origin, 404 missing resource, 409 state conflict, 410 expired request, 412 precondition, 413 size, 415 media type, 429 rate/quota, 5xx service failure.' },
    servers: [{ url: origin }],
    paths: Object.fromEntries(routes.map(route => [route.path, {
      ...Object.fromEntries(Object.entries(route.methods).map(([method, operation]) => {
        const pathParameters = [...route.path.matchAll(/\{(\w+)\}/g)].map(([, name]) => ({ name, in: 'path', required: true, schema: pathSchemas[name], ...(name === 'principalId' ? { description: 'Principal id, or me for the caller.' } : {}) }));
        const { 'x-input-error': ignored, ...published } = operation;
        return [method, { ...published, tags: [route.path.startsWith('/v1/') ? route.path.split('/')[2] : 'Server'], parameters: [...pathParameters, ...operation.parameters] }];
      })),
    }])),
    components: { schemas, securitySchemes: {
      bearer: { type: 'http', scheme: 'bearer', description: 'Foundation-issued private key (fdn_…). Not an OAuth token from a connected service.' },
      session: { type: 'apiKey', in: 'cookie', name: 'fdn_session', description: 'HttpOnly browser session from email sign-in. Writes require same-origin requests.' },
      requestLink: { type: 'apiKey', in: 'cookie', name: 'fdn_link', description: 'One store request only, after exchanging a one-use link. Cannot access other resources.' },
    } },
  };
}
