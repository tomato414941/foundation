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
  fields: { ...map({ anyOf: [string, object({ reference: id }, ['reference'])] }), description: 'token: the values the service\'s token scheme lists, by field name - each a value, or { reference: <secret id> } for a secret of the owner\'s (or one they may read) whose bytes are used, and whose line is looked at, every time.' }, name: { ...string, description: 'token: what to call the connection; defaults to the service name followed by のトークン.' } }, ['service']);
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
const resourceBase = { id: string, kind: choice(KINDS), name: string, owner_id: principalId, created_at: iso, updated_at: iso, lines: array(object({ subject_id: principalId, relation: string, created_at: iso }, ['subject_id', 'relation', 'created_at'])) };
const resource = (kind, fields) => object({ ...resourceBase, kind: { const: kind }, ...fields }, ['id', 'kind', 'name']);

export const schemas = {
  Error: object({ error: object({ code: string, message: string }, ['code', 'message']) }, ['error']),
  Ok: object({ ok: { const: true } }, ['ok']),
  Empty: object(),
  // An entry: how a principal is proven. Begun with POST /v1/credentials (kind says how), finished with PUT where the
  // kind needs a second step (a passkey's response, an email link), listed and removed alike.
  BeginCredential: { ...object({ kind: choice(['webauthn', 'email', 'key']), name: errorCode(string, 'invalid_name'), address: errorCode(string, 'invalid_email'), replaces: string, return_to: errorCode(string, 'invalid_return') }, ['kind']),
    description: 'webauthn: returns WebAuthn creation options (name labels the passkey in its authenticator; without one, for a principal yet to be made, a name is drawn - a role at a star). email: sends a link to address (anonymous: a sign-in link; as a principal: a link that attaches the address to it). key: issues a key and shows it once (anonymous: makes the principal named name with it; replaces revokes another key).' },
  CompleteCredential: { ...object({ kind: choice(['webauthn', 'email']), name: errorCode(string, 'invalid_name'), credential: { ...object(), description: 'webauthn: the RegistrationResponseJSON the authenticator made from the options.' }, wrap: { ...string, description: 'webauthn: the principal\'s private key wrapped with what this credential yields (PRF), base64url.' },
    public_key: { ...string, description: 'webauthn, anonymous: the new principal\'s public key, base64url.' }, principal_name: { ...string, description: 'webauthn, anonymous: the new principal\'s name; by default the one drawn into the options.' },
    email: errorCode(string, 'invalid_email'), token: errorCode(string, 'invalid_link'), session: choice(['cookie', 'token']), return_to: errorCode(string, 'invalid_return') }, ['kind']),
    description: 'Anonymous, webauthn: the credential makes a principal and a session (cookie with Origin, or an hour\'s token with session "token"). As a principal, webauthn: the credential is attached. email (from the link\'s page, same-origin): the address is attached to the principal that asked (attached: true, nobody signed in), else proven for the first time it makes a principal, else it signs its principal in; email_taken (409) when another principal has it - merge instead.' },
  Credential: object({ id: string, kind: choice(['webauthn', 'email', 'key']), name: nullable(string), created_at: iso, last_used_at: nullable(iso), environment: id }, ['id', 'kind', 'name', 'created_at', 'last_used_at']),
  CredentialDone: object({ ok: { const: true }, attached: boolean, principal: ref('Principal'), credential: ref('Credential'), backed_up: boolean, token: string, expires_at: time, return_to: string }),
  PendingSignin: object({ email: string, expires_at: time, resend_at: time }, ['email', 'expires_at', 'resend_at']),
  Payment: object({ available: boolean, paying: boolean, payer: { anyOf: [principalId, { type: 'null' }], description: 'Who pays for this principal\'s use: the one that took it on, else its owner\'s payer, else itself once it has registered a payment method, else null. The free part and the ceiling are counted for the payer; with none, nothing metered (environments, objects) can be used in this principal\'s name.' } }, ['available', 'paying', 'payer']),
  CreatePrincipal: { ...object({ name: string, alias: string, agent: boolean, steward: boolean }), description: 'name defaults to the alias, or 相手. alias is an idempotent local name. agent: true lets it use what the caller holds. steward: true makes a group: the caller stands as it. An entry for it (a key, a passkey) is added with POST /v1/credentials?as=<its id>.' },
  Rename: object({ name: resourceName }, ['name']),
  MergeBegun: object({ ticket: string, other: ref('Principal'), key: ref('PrincipalKey'), wrap: nullable(string), secrets: array(object({ id, name: string, envelope: nullable(string) }, ['id', 'name', 'envelope'])) }, ['ticket', 'other', 'key', 'wrap', 'secrets']),
  MergeComplete: object({ ticket: string, into: { ...choice(['this', 'other']), description: 'Which account remains: this (the session\'s, the default) or other (the passkey\'s). The one that does not remain ends.' }, envelopes: { ...map(string), description: 'The other\'s secrets\' keys sealed for this principal, by secret id.' }, wrap: { ...string, description: 'This principal\'s private key wrapped with what the passkey yielded.' }, public_key: { ...string, description: 'This principal\'s public key, when it had none: made now with that passkey.' } }, ['ticket']),
  MergeDone: object({ into: principalId, from: principalId, moved: object({ secrets: integer, connections: integer, objects: integer, apps: integer, services: integer, principals: integer, webauthn_credentials: integer, emails: integer }), principal: ref('Principal') }, ['into', 'from', 'moved', 'principal']),
  Transfer: object({ to: principalId, envelope: { ...string, description: 'For a secret: its key sealed for the new owner, base64url, as the giver made it.' } }, ['to']),
  Principal: object({ id: principalId, name: string, created_at: iso, alias: nullable(string),
    keys: array(ref('Key')), acts_for: array(principalId), owners: array(principalId), stewards: { ...array(principalId), description: 'Who stands as this principal: a group\'s people. Empty for one that comes in by itself.' } }, ['id', 'name', 'created_at']),
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
    recipients: { ...array(ref('Recipient')), description: 'For a store request: whom to seal each entry for.' },
  }, ['id', 'authorization_details', 'from', 'to', 'status', 'verification_uri', 'expires_at', 'interval']),
  GrantRequest: { anyOf: [
    object({ entries: array(object({ name: resourceName, content: string, envelopes: map(string) }, ['name', 'content'])) }, ['entries']),
    object({ user_code: string }), appValues,
  ], description: 'secret: entries in the requested field order, each sealed as a SecretInput for the asker and its recipients; relation: the user_code the asker showed, when the request was addressed to nobody; app: name, client_id, client_secret and service-specific top-level app fields. connection is granted through /v1/connections and the service consent flow. Wrong user codes, including missing ones, count toward the attempt limit.' },
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
    additionalProperties: false, description: 'A owner-defined service. auth_schemes may be empty; catalog adapters and role schemes cannot be registered here. URLs use RFC 6570; response selectors and injection values use RFC 6901 JSON Pointers. Endpoint variables come from declared app fields/client_id; identity URLs may also use access_token and kept fields, and revocation URLs access_token/refresh_token.' },
  AppInput: appValues,
  Secret: resource('secret', { size: integer, recipients: { ...array(principalId), description: 'Principals an envelope was made for: those that can open it.' } }),
  SecretInput: { anyOf: [
    object({ content: { ...string, description: 'The bytes sealed with the secret\'s own key, base64url.' }, envelopes: { ...map(string), description: 'The secret\'s key sealed per recipient (principal id to base64url envelope). Added to those kept.' } }, ['content']),
    object({ plain: { ...string, description: 'The bytes as they are, base64url, for Foundation\'s principal to seal for the owner and itself. Only where it is the owner\'s agent (otherwise foundation_not_agent).' } }, ['plain']),
  ], description: 'Sealed by the client, which opens nothing to the server; or, by a client that cannot seal, handed to Foundation\'s principal to seal. See /v1/recipients for whom to seal for.' },
  SecretContent: object({ content: string, envelope: { ...nullable(string), description: 'The caller\'s own envelope, when one was made for it.' }, recipients: { ...array(ref('Recipient')), description: 'Those with an envelope: a writer sealing with a new key seals it for each of them again.' } }, ['content', 'envelope', 'recipients']),
  PrincipalKey: object({ principal_id: principalId, public_key: nullable(string), wraps: { ...map(string), description: 'For the caller\'s own key: the private key wrapped per WebAuthn credential id, as kept.' } }, ['principal_id', 'public_key']),
  PublishKey: object({ public_key: string, wraps: { ...map(string), description: 'The private key wrapped per WebAuthn credential id, as the client made it.' } }, ['public_key']),
  Recipient: object({ principal_id: principalId, public_key: string }, ['principal_id', 'public_key']),
  Object: resource('object', { size: integer, type: nullable(string) }),
  Connection: resource('connection', { service: ref('ServiceSummary'), auth_scheme: scheme, status: string, label: string, references: { ...array(id), description: 'The secrets its fields refer to.' },
    facts: object(), variables: array(string), app: nullable(object({ id: string, name: string, foundation: boolean })), subject: nullable(string),
    generation: integer, expires_at: nullable(time), can_reconnect: boolean, can_revoke: boolean, available: boolean }),
  App: resource('app', { service: ref('ServiceSummary'), foundation: boolean, client_id: string, settings: map(string), connections: integer }),
  Service: resource('service', { definition: object(), service: ref('ServiceDescription'), dependents: integer }),
  Environment: resource('environment', { size: string, lifetime, identity: nullable(principalId), status: { ...choice(['starting', 'ready', 'busy', 'stopping', 'stopped']), description: 'stopping closes access immediately; stop confirmation and failed attempts are retried durably before stopped.' },
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
    payment: ref('Payment'), credentials: array(ref('Credential')), secrets: array(ref('Secret')), connections: array(ref('Connection')), apps: array(ref('App')), services: array(ref('Service')),
    catalog: array(ref('ServiceDescription')), principals: array(ref('Principal')), agents: array(ref('Principal')), requests: array(ref('Request')),
    functions: array(ref('Function')), settings: nullable(ref('Settings')), environments: array(ref('Environment')), compute: ref('Compute'), foundation: object({ principal_id: principalId }, ['principal_id']) },
    ['user', 'principal', 'payment', 'credentials', 'secrets', 'connections', 'apps', 'services', 'catalog', 'principals', 'agents', 'requests', 'functions', 'settings', 'environments', 'compute', 'foundation']),
  Export: object({ exported_at: iso, owner: nullable(string), origin: string,
    secrets: array({ allOf: [ref('Secret'), object({ content: string, encoding: { const: 'base64url' }, envelopes: map(string) }, ['content', 'encoding', 'envelopes'])] }),
    connections: array({ allOf: [ref('Connection'), object({ content: string, encoding: { const: 'base64url' }, envelopes: map(string) }, ['content', 'encoding', 'envelopes'])] }), services: array(object({ id, name: string, definition: object() })), principals: array(ref('Principal')) }, ['exported_at', 'owner', 'origin', 'secrets', 'connections', 'services', 'principals']),
};

const query = (name, schema = string, description, required = false) => ({ name, in: 'query', schema, required, ...(description ? { description } : {}) });
const header = (name, description) => ({ name, in: 'header', schema: string, description });
const json = schema => ({ 'application/json': { schema: typeof schema === 'string' ? ref(schema) : schema } });
const response = (schema, description = 'Success') => ({ description, content: json(schema) });
const body = schema => ({ required: true, content: json(schema) });
const secure = [{ bearer: [] }, { session: [] }], session = [{ session: [] }];
const as = query('as', principalId, 'Principal whose resources to use. Defaults to the caller. Requires an agent relation or the relevant resource permission. CLI/MCP select it automatically only when acts_for has exactly one entry.');
// status: the success status, or every one an operation answers with (the same shape for each).
function op(operationId, summary, output, { input, status = 200, description, parameters = [], security = secure, ...rest } = {}) {
  return { operationId, summary, ...(description ? { description } : {}), security, parameters,
    ...(input ? { requestBody: body(input) } : {}), responses: { ...Object.fromEntries([].concat(status).map(code => [code, response(output)])), default: response('Error', 'Failure. error.code is stable; error.message is display text. State-dependent failures may include additional fields.') }, ...rest };
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
  { name: 'session', path: '/v1/session', methods: {
    get: op('getSession', 'Read how one may sign in here, and the email sign-in being waited for', object({ available: boolean, method: { const: 'email_link' }, pending: nullable(ref('PendingSignin')) }, ['available', 'method', 'pending']), { security: [] }),
    post: op('beginSignin', 'Start signing in with a WebAuthn credential', object({ options: object() }, ['options']), { input: object({ kind: { const: 'webauthn' } }, ['kind']), security: [], 'x-input-error': 'invalid_kind', description: 'WebAuthn request options (PublicKeyCredentialRequestOptionsJSON). Any registered WebAuthn credential may answer. Signing in by email is POST /v1/credentials {kind: "email"} without a session: the link signs in.' }),
    put: op('signin', 'Sign in with a WebAuthn credential', object({ ok: { const: true }, return_to: string, token: string, expires_at: time }), { input: object({ kind: { const: 'webauthn' }, credential: { ...object(), description: 'The AuthenticationResponseJSON answering the options.' }, session: choice(['cookie', 'token']), return_to: errorCode(string, 'invalid_return') }, ['kind', 'credential']), security: [], 'x-input-error': 'invalid_webauthn_credential',
      description: 'A browser (session "cookie", the default) gets a session cookie and must send Origin; a program (session "token") gets a bearer session token that lasts an hour.' }),
    delete: op('signout', 'End this browser session, or the email sign-in being waited for', object({ ok: { const: true } }, ['ok']), { security: [] }),
  } },
  { name: 'catalog', path: '/v1/services', methods: { get: op('listCatalog', 'List built-in services and connection methods', many('services', 'ServiceDescription'), { security: [] }) } },
  { name: 'return', path: '/v1/requests/{requestId}/return', methods: { get: op('getRequestReturn', 'Read the return destination for a request', result('back', object({ name: string, return_url: string, refresh_url: string }, ['name', 'return_url', 'refresh_url'])), { security: [] }) } },
  { name: 'exchangeLink', path: '/v1/links/exchange', methods: { post: okay('exchangeLink', 'Exchange a one-use request link for a request-scoped cookie', { input: object({ link: string, request_id: requestId }, ['link', 'request_id']), security: [], 'x-input-error': 'invalid_link' }) } },
  { name: 'credentials', path: '/v1/credentials', methods: {
    get: op('listCredentials', 'List the entries a principal is proven by: passkeys, addresses, keys', object({ credentials: array(ref('Credential')) }, ['credentials']), { parameters: [as] }),
    post: op('beginCredential', 'Begin adding an entry - or, without a session, becoming a principal by one', object({ options: object(), pending: ref('PendingSignin'), principal: ref('Principal'), credential: ref('Credential'), token: string }), { input: 'BeginCredential', status: [200, 201, 202], security: [{}, ...secure], parameters: [as], 'x-input-error': 'invalid_kind',
      description: 'Anyone may become a principal, saying nothing of who they are: an entry proven by nobody makes one. The same call by a principal (or whoever decides for it) adds the entry to it. The CLI\'s init does this with a WebAuthn credential of its own; a browser\'s "start with a passkey" does the same.' }),
    put: op('completeCredential', 'Finish adding an entry that takes a second step: a passkey\'s response, or an email link opened', 'CredentialDone', { input: 'CompleteCredential', status: [200, 201], security: [{}, ...secure], parameters: [as], 'x-input-error': 'invalid_kind' }),
  } },
  { name: 'credential', path: '/v1/credentials/{credentialId}', methods: { delete: okay('removeCredential', 'Remove an entry of any kind; the sessions it proved end') } },
  { name: 'credentialWrap', path: '/v1/credentials/{credentialId}/wrap', methods: { put: okay('keepWrap', 'Keep the principal\'s private key wrapped for this passkey', { input: object({ wrapped: string }, ['wrapped']), 'x-input-error': 'invalid_wrap' }) } },
  { name: 'mergeOptions', path: '/v1/merge/options', methods: { post: op('mergeOptions', 'Start merging with another account: options its passkeys may answer', object({ options: object() }, ['options']), { input: object({ principal_id: principalId }, ['principal_id']), 'x-input-error': 'invalid_merge', description: 'The other account, by id. Only its passkeys may answer; an account with none is refused (no_passkey).' }) } },
  { name: 'mergeBegin', path: '/v1/merge', methods: { post: op('mergeBegin', 'Prove the other account by its passkey and learn what it has', 'MergeBegun', { input: object({ credential: object(), principal_id: principalId }, ['credential']), 'x-input-error': 'invalid_webauthn_credential', description: 'The passkey must be another principal\'s. Returns a ticket for completing, the other\'s key wrapped for that passkey (to open its secrets\' envelopes with what the passkey yields), and its secrets with their envelopes for it, so that they can be sealed anew for this principal.' }) } },
  { name: 'mergeComplete', path: '/v1/merge/complete', methods: { post: op('mergeComplete', 'Make the two accounts one', 'MergeDone', { input: 'MergeComplete', 'x-input-error': 'invalid_merge', description: 'Everything the ending account owns, the principals it owns, its passkeys and addresses become the remaining one\'s; the ending one ends, with the lines it drew and was drawn, and its sessions. A name the remaining one already uses refuses the whole (name_taken).' }) } },
  { name: 'key', path: '/v1/key', methods: {
    get: op('getKey', 'Read the caller\'s public key and its private key wrapped per credential', object({ key: ref('PrincipalKey') }, ['key'])),
    put: op('publishKey', 'Publish the caller\'s public key, once', object({ key: ref('PrincipalKey') }, ['key']), { input: 'PublishKey', 'x-input-error': 'invalid_key', description: 'A principal has one key; envelopes are made for it. Replacing it is refused (key_exists).' }),
  } },
  { name: 'recipients', path: '/v1/recipients', methods: { get: op('listRecipients', 'Whom a secret kept by the owner is sealed for', object({ recipients: array(ref('Recipient')) }, ['recipients']), { parameters: [as], description: 'The owner, and Foundation\'s principal when it is the owner\'s agent, each with a public key. Make an envelope for each when placing a secret.' }) } },
  { name: 'payment', path: '/v1/payment', methods: { get: op('getPayment', 'Read whether the owner pays for use beyond the free part', object({ payment: ref('Payment') }, ['payment']), { parameters: [as] }) } },
  { name: 'paymentEvents', path: '/v1/payment/events', methods: { post: op('paymentEvents', 'Receive Stripe events', object({ received: { const: true } }, ['received']), { input: object(), security: [], 'x-input-error': 'invalid_signature',
    description: 'For Stripe only: events signed with the endpoint secret (Stripe-Signature). Subscription changes set whether a principal pays.' }) } },
  { name: 'paymentSetup', path: '/v1/payment/setup', methods: { post: op('setUpPayment', 'Start setting a payment method', object({ url: string }, ['url']), { input: 'Empty', parameters: [as],
    description: 'Returns the address of Stripe\'s page for setting a payment method. Coming back, the page carries the session id to POST to /v1/payment/complete.' }) } },
  { name: 'paymentComplete', path: '/v1/payment/complete', methods: { post: op('completePayment', 'Finish setting a payment method', object({ payment: ref('Payment') }, ['payment']), { input: object({ session_id: string }, ['session_id']), parameters: [as], 'x-input-error': 'invalid_payment' }) } },
  { name: 'me', path: '/v1/principals/me', methods: {
    get: op('getMe', 'Read the caller and its current access', 'Me'), patch: op('renameMe', 'Rename the caller', one('Principal'), { input: 'Rename', 'x-input-error': 'invalid_name' }),
    delete: okay('removeMe', 'Remove the caller and its resources'),
  } },
  { name: 'principals', path: '/v1/principals', methods: {
    get: op('listPrincipals', 'List principals owned by the caller', many('principals', 'Principal')),
    post: op('createPrincipal', 'Make a principal of the caller\'s own', one('Principal'), { input: 'CreatePrincipal', status: 201, 'x-input-error': 'invalid_name',
      description: 'The caller becomes its owner. It has no entry until one is added with POST /v1/credentials?as=<its id> (a key shown once, or a passkey). Becoming a principal by oneself is POST /v1/credentials without a session. To ask someone for access, a principal uses POST /v1/requests with {"authorization_details":[{"type":"relation","relation":"agent"}]} and gives them the returned verification_uri and user_code; GET /v1/principals/me reports acts_for afterward. The CLI performs the bootstrap: foundation init <server> --name <name> makes the principal, foundation join asks for approval.' }),
  } },
  { name: 'principal', group: 'principals', path: '/v1/principals/{principalId}', methods: {
    get: op('getPrincipal', 'Read a principal', one('Principal')), patch: op('renamePrincipal', 'Rename a principal', one('Principal'), { input: 'Rename', 'x-input-error': 'invalid_name' }), delete: okay('removePrincipal', 'Remove an owned principal and its resources'),
  } },
  { name: 'transferPrincipal', group: 'principals', path: '/v1/principals/{principalId}/transfer', methods: { post: op('transferPrincipal', 'Give an owned principal to another principal', one('Principal'), { input: 'Transfer', 'x-input-error': 'invalid_transfer', description: 'By its owner. The owner\'s record and alias move; the principal\'s own lines and keys stay.' }) } },
  { name: 'publicKey', group: 'principals', path: '/v1/principals/{principalId}/public-key', methods: { get: op('getPublicKey', 'Read a principal\'s public key', object({ key: ref('PrincipalKey') }, ['key'])) } },
  { name: 'links', group: 'principals', path: '/v1/principals/{principalId}/links', methods: { post: op('issueLink', 'Issue a one-use link for a store request', object({ link: object({ id, request_id: requestId, expires_at: time }, ['id', 'request_id', 'expires_at']), url: string, expires_at: time }, ['link', 'url', 'expires_at']), { input: object({ request_id: string }, ['request_id']), status: 201, 'x-input-error': 'invalid_request' }) } },
  { name: 'access', group: 'principals', path: '/v1/principals/{principalId}/access', methods: { delete: okay('revokeAccess', 'Revoke a principal’s access to the owner', { parameters: [as] }) } },
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
    post: op('createRequest', 'Ask someone for a relation, secrets, a connected service or a registered app', one('Request'), { input: 'CreateRequest', status: 201, parameters: [as], 'x-input-error': 'invalid_authorization_details', description: 'authorization_details holds one detail (RFC 9396). A relation with no object, asked of nobody, is how a principal nobody knows asks to act for whoever answers; it returns a user_code to show beside verification_uri (as in RFC 8628). Otherwise the request goes to to, the owner of the object, or the owner selected by as, who answers where they are (as in CIBA); binding_message tells them why. Poll GET /v1/requests/{requestId} no more often than interval seconds; faster polling is answered with slow_down, and an expired request with expired_token. Do not collect secrets in chat.' }),
  } },
  { name: 'request', group: 'requests', path: '/v1/requests/{requestId}', methods: {
    get: op('getRequest', 'Read a request and its outcome', one('Request'), { security: [...secure, { requestLink: [] }] }),
    delete: op('cancelRequest', 'Cancel a sent request', one('Request'), { input: 'Empty' }),
  } },
  { name: 'grant', group: 'requests', path: '/v1/requests/{requestId}/grant', methods: { post: op('grantRequest', 'Grant a request as the one asked', { anyOf: [one('Request'), object({ stored: { const: true }, names: array(string), replaced: array(string) }, ['stored', 'names', 'replaced']), object({ registered: { const: true }, app_id: id }, ['registered', 'app_id'])] }, { input: 'GrantRequest', security: [...secure, { requestLink: [] }], description: 'Request-link cookies may answer only their own request. App registration requires a browser session. A relation is drawn only where the one granting may draw it. Wrong user codes count toward the attempt limit.' }) } },
  { name: 'deny', group: 'requests', path: '/v1/requests/{requestId}/deny', methods: { post: op('denyRequest', 'Decline a received request', one('Request'), { input: 'Empty', security: [...secure, { requestLink: [] }] }) } },
  { name: 'relations', path: '/v1/relations', methods: {
    get: op('listRelations', 'List the caller’s relations', many('relations', 'Relation')),
    post: okay('addRelation', 'Grant a role or action on a principal or resource', { input: 'RelationInput', status: 201, 'x-input-error': 'invalid_relation', description: 'subject defaults to the caller. Roles include agent on principals and viewer/editor on resources. Specific actions may also be granted. The caller must be able to share the target and exercise everything the new relation grants. Ownership is not granted through this endpoint.' }),
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
    delete: okay('removeEnvironment', 'Close and remove an execution environment', { description: 'Returns success only after the runner confirms removal. If it cannot yet confirm, returns 503 environment_stopping and retains the environment with access revoked; stopping and removal retry automatically, including after restart.' }),
  } },
  { name: 'commands', group: 'environments', path: '/v1/environments/{resourceId}/commands', methods: { post: op('startCommand', 'Run a command in an environment', one('Command'), { input: 'CommandInput', 'x-input-error': 'invalid_command', responses: { 200: response(one('Command')), 202: response(one('Command'), 'Still running after 20 seconds; poll by command id.'), default: response('Error', 'Failure') } }) } },
  { name: 'command', group: 'environments', path: '/v1/environments/{resourceId}/commands/{commandId}', methods: { get: op('getCommand', 'Read command status and output', one('Command')) } },
  { name: 'resources', path: '/v1/resources', methods: {
    get: op('listResources', 'List resources or find one by literal name', { anyOf: [many('resources', 'Resource'), one('Resource')] }, {
      parameters: [as, query('kind', choice(KINDS)), query('name', string, 'Exact name lookup for secret, object, service or app; returns resource (singular).'), query('prefix', string), query('service', string, 'Filter connections by service id.'), query('shown', string, 'me lists resources shared with the caller.')],
      description: 'Connection metadata contains no renewable state or token. Apps may include the built-in Foundation app. Without name the result is resources (an array).' }),
    put: op('putResource', 'Create or replace a resource by kind and name', one('Resource'), { parameters: [as, query('kind', choice(['secret', 'object', 'app', 'service']), undefined, true), query('name', resourceName, undefined, true), header('If-Match', 'Secret revision from ETag; mismatch returns 412 secret_changed.'), header('If-None-Match', 'Use * to create a service only when its name is unused; otherwise 412 name_taken.')],
      description: 'kind determines the body: object stores raw bytes (including when Content-Type is application/json); secret, app and service parse JSON. A secret is placed sealed (SecretInput), 1 byte–1 MiB; objects allow up to 25 MiB and preserve Content-Type. Managed connections are created through /v1/connections, not here.',
      requestBody: { required: true, content: { ...rawContent, 'application/json': { schema: { anyOf: [ref('SecretInput'), ref('ServiceDefinition'), ref('AppInput')], description: 'SecretInput for kind=secret; ServiceDefinition for kind=service; AppInput for kind=app.' } } } },
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
    get: op('getContent', 'Read a secret as sealed, or download object bytes', 'Empty', { responses: { 200: { description: 'A secret: its sealed bytes and the caller\'s envelope (application/json, SecretContent). An object: its bytes (stored Content-Type).', content: { ...rawContent, 'application/json': { schema: ref('SecretContent') } }, headers: etag }, default: response('Error', 'Failure') } }),
    put: op('putContent', 'Replace a secret\'s sealed bytes or an object\'s bytes', one('Resource'), { requestBody: { required: true, content: { ...rawContent, 'application/json': { schema: ref('SecretInput') } } }, parameters: [header('If-Match', 'Expected secret revision from ETag.')], responses: { 200: { ...response(one('Resource')), headers: etag }, default: response('Error', 'Failure') } }),
  } },
  { name: 'envelopes', group: 'resources', path: '/v1/resources/{resourceId}/envelopes/{principalId}', methods: {
    put: okay('keepEnvelope', 'Keep the secret\'s key sealed for a principal, as the caller sealed it', { input: object({ wrapped: string }, ['wrapped']), 'x-input-error': 'invalid_envelope' }),
    post: okay('resealEnvelope', 'Have Foundation seal the secret\'s key for a principal, from the envelope made for Foundation', { input: 'Empty', description: 'Only for a secret sealed for Foundation\'s principal (otherwise not_sealed_for_foundation), and for a principal with a key (otherwise no_key).' }),
    delete: okay('dropEnvelope', 'Take back the envelope made for a principal'),
  } },
  { name: 'transferResource', group: 'resources', path: '/v1/resources/{resourceId}/transfer', methods: { post: op('transferResource', 'Give a resource to another principal', one('Resource'), { input: 'Transfer', 'x-input-error': 'invalid_transfer', description: 'By whoever may transfer it (its owner, or one given that action). The lines onto it stay. A secret goes with an envelope for the new owner when given, or one Foundation makes from its own; a connection or app is resealed for them; a service goes only when nothing refers to it; an environment is not given.' }) } },
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
  { name: 'overview', path: '/v1/overview', methods: { get: op('getOverview', 'Read the owner’s workspace', 'Overview', { parameters: [as] }) } },
  { name: 'export', path: '/v1/export', methods: { get: op('exportData', 'Download the owner’s data, including secret bytes', 'Export', { parameters: [as], description: 'Secrets and connection states go out as kept: sealed, with their envelopes; they open with the owner\'s key where an envelope was made for them. Handle as private data.' }) } },
];

// A WebAuthn credential is known by the id its authenticator gave it (base64url, up to 1023 bytes).
const credentialId = { type: 'string', pattern: '^[A-Za-z0-9_-]{16,1364}$' };
const pathSchemas = { principalId, requestId, resourceId: id, keyId: id, commandId: id, credentialId };
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
