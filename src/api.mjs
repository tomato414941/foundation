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
const connect = object({ service: string, auth_scheme: scheme, connection_id: id, scopes, app,
  fields: { ...map({ anyOf: [string, object({ reference: id }, ['reference'])] }), description: 'token: the values the service\'s token scheme lists, by field name - each a value, or { reference: <secret id> } for a secret of the owner\'s (or one they may read) whose bytes are used, and whose line is looked at, every time.' }, name: { ...string, description: 'token: what to call the connection; defaults to the service name followed by のトークン.' } }, ['service']);
const requestProperties = {
  to: errorCode(principalId, 'invalid_principal'), binding_message: errorCode({ type: 'string', maxLength: 240 }, 'invalid_purpose'), steps: errorCode({ type: ['array', 'null'], items: errorCode(string, 'invalid_steps'), maxItems: 20 }, 'invalid_steps'),
  valid_minutes: errorCode({ type: ['integer', 'null'], description: 'Expiry in minutes; default 30, from 1 to 1440. null uses the default.' }, 'invalid_validity'),
};
// A call a request asks for, as the one asked would send it, and where they supply what only they have.
const requestInput = object({ at: { ...string, description: 'Where in body the value goes (JSON Pointer). "" is the whole body, for a sealed secret.' },
  label: { ...string, description: 'What to ask the one asked for, in their words: 1-60 characters.' },
  kind: { ...choice(['text', 'hidden', 'sealed']), description: 'text: typed and shown. hidden: typed and not shown. sealed: typed and sealed by their own client for those who may open it, placed as a SecretInput (content, envelopes). text by default.' },
  multiline: boolean, site: { ...string, description: 'An https page where the value is made or found.' } }, ['at', 'label']);
const call = object({ method: choice(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']), path: { ...string, description: 'A path of this API, with its query. me in it means the one who makes the call: the one asked.' },
  body: object(), inputs: { ...array(requestInput), maxItems: 16 } }, ['method', 'path']);
const appValues = { ...object({ service: string, name: resourceName, client_id: string, client_secret: { ...string, writeOnly: true } }),
  description: 'Client fields are top-level keys. Additional service-specific keys (for example runame or domain) are declared by app_fields in GET /v1/services or the service resource. Client secrets are write-only.' };
const lifetime = errorCode(nullable(object({ end: errorCode(nullable(choice(['exit', 'idle'])), 'invalid_lifetime'), idle_seconds: errorCode(nullable(integer), 'invalid_lifetime'), max_seconds: errorCode(nullable(integer), 'invalid_lifetime') })), 'invalid_lifetime');
const command = { command: errorCode({ ...array(string), minItems: 1 }, 'invalid_command'), stdin: errorCode(nullable(string), 'invalid_stdin'), timeout_seconds: errorCode(nullable(integer), 'invalid_timeout'),
  inputs: { ...errorCode({ ...array(ref('InjectionInput')), minItems: 1, maxItems: 16 }, 'invalid_names'), description: 'Secrets and connections handed to this command alone, as in POST /v1/principals/{principalId}/injections: a variable, or a file whose path is the variable. Taken out of what it prints.' } };
const environment = { name: resourceName, image: { ...errorCode(nullable(string), 'invalid_image'), description: 'An OCI image reference, such as python:3.12-slim. It needs sh and the usual commands (cat, base64, mkdir). Foundation\'s general one when left out.' }, size: errorCode(nullable(choice(['small', 'medium', 'large'])), 'invalid_size'), lifetime, identity: errorCode(nullable(principalId), 'invalid_principal') };
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
  // An entry: how a principal is proven. Begun with POST (kind says how), finished with PUT where the kind takes a second
  // step, listed and removed alike. A principal's entries are under it; an entry that is nobody's yet makes a principal
  // (POST /v1/principals) or, being someone's already, signs them in (the session).
  BeginCredential: { ...object({ kind: choice(['webauthn', 'email', 'key']), address: errorCode(string, 'invalid_email'), replaces: string }, ['kind']),
    description: 'webauthn: returns WebAuthn creation options. email: sends a link to address; opening it (PUT /v1/session) attaches the address to this principal and signs nobody in. key: issues a key and shows it once; replaces revokes another.' },
  CompleteCredential: object({ kind: { const: 'webauthn' }, name: errorCode(string, 'invalid_name'), credential: { ...object(), description: 'The RegistrationResponseJSON the authenticator made from the options.' },
    wrap: { ...string, description: 'The principal\'s private key wrapped with what this credential yields (PRF), base64url.' } }, ['kind', 'name', 'credential']),
  Become: { ...object({ kind: choice(['webauthn', 'key']), name: errorCode(string, 'invalid_name'), alias: string, agent: boolean, member: boolean }),
    description: 'With a session or key: makes a principal the caller owns (name defaults to the alias, or one drawn at random; alias is an idempotent local name; agent: true lets it use what the caller holds; member: true makes a group the caller stands as). Without one, kind says how one becomes a principal by oneself: webauthn returns WebAuthn creation options (name labels the passkey; without one a name is drawn, a role at a star); key makes the principal named name and shows its key once.' },
  BecomeComplete: object({ kind: { const: 'webauthn' }, name: errorCode(string, 'invalid_name'), principal_name: { ...string, description: 'The new principal\'s name; by default the one drawn into the options.' }, credential: { ...object(), description: 'The RegistrationResponseJSON the authenticator made from the options.' },
    wrap: { ...string, description: 'The new principal\'s private key wrapped with what this credential yields (PRF), base64url.' }, public_key: { ...string, description: 'The new principal\'s public key, base64url.' }, session: choice(['cookie', 'token']), return_to: errorCode(string, 'invalid_return') }, ['kind', 'name', 'credential']),
  BeginSignin: object({ kind: choice(['webauthn', 'email']), address: errorCode(string, 'invalid_email'), return_to: errorCode(string, 'invalid_return') }, ['kind']),
  Signin: object({ kind: choice(['webauthn', 'email']), credential: { ...object(), description: 'webauthn: the AuthenticationResponseJSON answering the options.' }, email: errorCode(string, 'invalid_email'), token: errorCode(string, 'invalid_link'), session: choice(['cookie', 'token']), return_to: errorCode(string, 'invalid_return') }, ['kind']),
  Credential: object({ id: string, kind: choice(['webauthn', 'email', 'key']), name: nullable(string), created_at: iso, last_used_at: nullable(iso), environment: id }, ['id', 'kind', 'name', 'created_at', 'last_used_at']),
  CredentialDone: object({ credential: ref('Credential'), backed_up: boolean }, ['credential']),
  Became: object({ options: object(), principal: ref('Principal'), credential: ref('Credential'), backed_up: boolean, token: string, expires_at: time, return_to: string }),
  SignedIn: object({ ok: { const: true }, options: object(), pending: ref('PendingSignin'), attached: boolean, return_to: string, token: string, expires_at: time }),
  PendingSignin: object({ email: string, expires_at: time, resend_at: time }, ['email', 'expires_at', 'resend_at']),
  Payment: object({ available: boolean, paying: boolean, payer: { anyOf: [principalId, { type: 'null' }], description: 'Who pays for this principal\'s use: the one that took it on, else its owner\'s payer, else itself once it has registered a payment method, else null. The free part and the ceiling are counted for the payer; with none, nothing metered (environments, objects) can be used in this principal\'s name.' } }, ['available', 'paying', 'payer']),
  Rename: object({ name: resourceName }, ['name']),
  MergeBegun: object({ ticket: string, other: ref('Principal'), key: ref('PrincipalKey'), wrap: nullable(string), secrets: array(object({ id, name: string, envelope: nullable(string) }, ['id', 'name', 'envelope'])) }, ['ticket', 'other', 'key', 'wrap', 'secrets']),
  MergeComplete: object({ into: { ...choice(['this', 'other']), description: 'Which account remains: this (the session\'s, the default) or other (the passkey\'s). The one that does not remain ends.' }, envelopes: { ...map(string), description: 'The other\'s secrets\' keys sealed for this principal, by secret id.' }, wrap: { ...string, description: 'This principal\'s private key wrapped with what the passkey yielded.' }, public_key: { ...string, description: 'This principal\'s public key, when it had none: made now with that passkey.' } }),
  MergeDone: object({ into: principalId, from: principalId, moved: object({ secrets: integer, connections: integer, objects: integer, apps: integer, services: integer, principals: integer, webauthn_credentials: integer, emails: integer }), principal: ref('Principal') }, ['into', 'from', 'moved', 'principal']),
  Transfer: object({ to: principalId, envelope: { ...string, description: 'For a secret: its key sealed for the new owner, base64url, as the giver made it.' } }, ['to']),
  Principal: object({ id: principalId, name: string, created_at: iso, alias: nullable(string),
    keys: array(ref('Key')), acts_for: array(principalId), owners: array(principalId), members: { ...array(principalId), description: 'Who stands as this principal: a group\'s people. Empty for one that comes in by itself.' },
    payer: { ...nullable(object({ id: principalId, name: string }, ['id', 'name'])), description: 'Who bears what it uses beyond the free part: itself, one who took that on, or its owner\'s payer. null when nobody does.' } }, ['id', 'name', 'created_at']),
  Key: object({ id, kind: { const: 'key' }, created_at: iso, last_used_at: nullable(iso), environment: nullable(id), environment_id: id, expires_at: time }, ['id']),
  Line: object({ relation: string, direction: { ...choice(['from', 'to']), description: 'from: drawn by the principal asked about. to: drawn toward it.' }, created_at: iso,
    principal: { ...object({ id: principalId, name: string }, ['id', 'name']), description: 'The principal at the other end.' }, resource: { ...object({ id, kind: nullable(string), name: string, owner_id: nullable(principalId) }, ['id', 'name']), description: 'The thing at the other end, for a line drawn onto one, and who holds it.' },
    alias: { ...string, description: 'On a line of ownership from the owner: the name the owner gave what it owns, when it gave one.' } }, ['relation', 'direction', 'created_at']),
  Relation: object({ subject_id: principalId, relation: string, object_type: choice(['principal', 'resource']), object_id: string, created_at: iso }, ['relation', 'object_type', 'object_id']),
  RelationInput: object({ relation: string, object_type: choice(['principal', 'resource']), object_id: { ...string, description: 'A principal or a resource by id; me for the caller.' } }, ['relation', 'object_type', 'object_id']),
  Call: call,
  CreateRequest: errorCode(object({ ...requestProperties, operations: errorCode({ ...array(ref('Call')), minItems: 1, maxItems: 8 }, 'invalid_operations') }, ['operations']), 'invalid_operations'),
  Request: object({ id: requestId, operations: array({ allOf: [ref('Call'), object({ operation_id: nullable(string), summary: string })] }), results: { ...array(nullable(object({ status: integer, body: nullable(object()) }, ['status', 'body']))), description: 'What each call answered once made, in order; null until then.' },
    from: principalId, to: nullable(principalId),
    binding_message: string, steps: array(string), status: choice(['pending', 'granted', 'denied', 'cancelled']), created_at: time, expires_at: time, expires_in: integer, interval: integer,
    verification_uri: string, requester_name: string, user_code: string, reason: string,
    events: array(object({ event: string, at: time, detail: object() })),
    names: { ...map(object({ type: choice(['principal', 'resource']), kind: string, name: string }, ['type', 'name'])), description: 'For the one asked: who or what each id in the calls is.' },
    recipients: { ...array(ref('Recipient')), description: 'For the one asked, when a call keeps a sealed secret: whom to seal it for.' },
  }, ['id', 'operations', 'results', 'from', 'to', 'status', 'verification_uri', 'expires_at', 'interval']),
  GrantRequest: { ...object({ values: { ...array(map({})), description: 'Per call, in order: what the one answering supplies, by each input\'s at - a string, or for a sealed input a SecretInput.' },
    user_code: { ...string, description: 'The code the asker showed, when the request was addressed to nobody. Wrong codes count toward the attempt limit.' } }),
    description: 'Makes the calls asked for, in order, as the one answering. A call that begins a service\'s consent returns continue (where to go); the request is answered when it comes back. A call that fails stops here with its error; answering again goes on from it.' },
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
  KeptFunction: resource('function', { description: string, parameters: map(object({ description: string, required: boolean })), request: object(), query: map(array({})) }),
  FunctionDefinition: { ...object({ description: { type: 'string', maxLength: 500 },
    parameters: { ...map(object({ description: { type: 'string', maxLength: 300 }, required: boolean })), description: 'The arguments a caller gives, by name: lower-case letters, digits and underscores.' },
    request: { ...object(), description: 'The HTTPS request it sends, as FetchInput without save. A binding part may also be { "parameter": name }, where an argument goes.' },
    query: { ...map(array({})), description: 'Query parameters added to the URL: each a list of strings and { "parameter": name } parts.' } }, ['request']), additionalProperties: false,
    description: 'One decided operation. Whoever calls it gives only its arguments; the destination, the method and the connections and secrets it uses (the owner\'s own) are fixed here.' },
  Environment: resource('environment', { image: nullable(string), size: string, lifetime, identity: nullable(principalId), status: { ...choice(['starting', 'ready', 'busy', 'stopping', 'stopped']), description: 'stopping closes access immediately; stop confirmation and failed attempts are retried durably before stopped.' },
    started_at: nullable(iso), last_active_at: nullable(iso), expires_at: nullable(iso) }),
  Resource: { oneOf: ['Secret', 'Object', 'Connection', 'App', 'Service', 'Environment', 'KeptFunction'].map(ref) },
  PatchResource: { ...object({ name: resourceName, identity: { ...nullable(principalId), description: 'For an environment: the principal it runs as, or null to take it away.' }, auth_schemes: object({ oauth: ref('OAuthDefinition') }), client_id: string, client_secret: string }), description: 'Apps also accept their service-specific top-level client fields, as declared by app_fields.' },
  DeleteResource: object({ revoke: boolean, confirm: boolean }),
  Connect: { ...connect, description: 'oauth and role need a browser session and return where to go next. token connects at once with the given fields; with connection_id it replaces that connection\'s values. To ask a person to connect, ask for this call at POST /v1/requests.' },
  ConnectResult: object({ url: string, state: string, connection: ref('Connection') }),
  Confirmation: object({ connection: ref('Connection'), changes: array(object()) }, ['connection', 'changes']),
  CreateEnvironment: object(environment),
  Run: { anyOf: [object({ ...environment, ...command }, ['command']), { ...object({ request: ref('FetchInput') }, ['request']), additionalProperties: false }],
    description: 'One thing run once: a command, on a machine lent for it; or an HTTPS request, sent from Foundation with no machine.' },
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
  Usage: object({ secrets: ref('StorageUsage'), objects: nullable(ref('StorageUsage')) }, ['secrets', 'objects']),
  StorageUsage: object({ count: integer, bytes: integer, count_max: integer, bytes_max: integer }, ['count', 'bytes', 'count_max', 'bytes_max']),
  AuditEntry: object({ id, actor_id: string, action: string, object_type: string, object_id: string, detail: object(), at: iso }, ['id', 'actor_id', 'action', 'object_type', 'object_id', 'detail', 'at']),
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
  { name: 'sessionChallenges', path: '/v1/session/challenges', methods: {
    post: op('beginSignin', 'Start signing in by proving an entry', 'SignedIn', { input: 'BeginSignin', status: [200, 202], security: [], 'x-input-error': 'invalid_kind', description: 'webauthn: returns WebAuthn request options (PublicKeyCredentialRequestOptionsJSON); any registered credential may answer. email: sends a single-use link to address (202, pending); a browser must send Origin.' }),
  } },
  { name: 'session', path: '/v1/session', methods: {
    get: op('getSession', 'Read how one may sign in here, the email sign-in being waited for, and who the caller is', object({ available: boolean, method: { const: 'email_link' }, pending: nullable(ref('PendingSignin')), current: { ...nullable(object({ principal_id: principalId, via: object({ kind: choice(['session', 'key']), id: string, environment: id }, ['kind', 'id']) }, ['principal_id', 'via'])), description: 'Who the caller is and what it came in by: a session, or a key (with the environment it was issued to, when it was). null for nobody.' } }, ['available', 'method', 'pending', 'current']), { security: [] }),
    post: op('signin', 'Sign in with what answers the challenge', 'SignedIn', { input: 'Signin', security: [], 'x-input-error': 'invalid_kind',
      description: 'webauthn: a browser (session "cookie", the default) gets a session cookie and must send Origin; a program (session "token") gets a bearer session token that lasts an hour. email (from the link\'s page, same-origin): an address proven for the first time makes a principal and signs it in; one proven before signs its principal in; a link a principal asked for (POST /v1/principals/{id}/credentials) attaches the address to it and signs nobody in (attached: true). email_taken (409) when another principal has the address: merge the two instead.' }),
    delete: op('signout', 'End this browser session, or the email sign-in being waited for', object({ ok: { const: true } }, ['ok']), { security: [] }),
  } },
  { name: 'catalog', path: '/v1/services', methods: { get: op('listCatalog', 'List built-in services and connection methods', many('services', 'ServiceDescription'), { security: [] }) } },
  { name: 'environmentImages', path: '/v1/environment-images', methods: { get: op('searchEnvironmentImages', 'Search public Docker Hub images', object({ images: array(object({ name: string, description: string, official: boolean }, ['name', 'description', 'official'])), next: nullable(integer) }, ['images', 'next']), {
    parameters: [query('query', string, 'Image search, up to 200 characters.'), query('page', integer, 'Page number, starting at 1.')],
  }) } },
  { name: 'environmentImageTags', path: '/v1/environment-images/tags', methods: { get: op('listEnvironmentImageTags', 'List Linux amd64 tags of a public Docker Hub image', object({ tags: array(object({ name: string }, ['name'])), next: nullable(integer), default_tag: { ...nullable(string), description: 'On the first unfiltered page: latest if that tag supports Linux amd64, otherwise null.' } }, ['tags', 'next']), {
    parameters: [query('repository', string, 'Docker Hub repository, such as python or a namespace/name.', true), query('query', string, 'Filter tag names.'), query('page', integer, 'Page number, starting at 1.')],
  }) } },
  { name: 'return', path: '/v1/requests/{requestId}/return', methods: { get: op('getRequestReturn', 'Read the return destination for a request', result('back', object({ name: string, return_url: string, refresh_url: string }, ['name', 'return_url', 'refresh_url'])), { security: [] }) } },
  { name: 'exchangeLink', path: '/v1/links/exchange', methods: { post: okay('exchangeLink', 'Exchange a one-use request link for a request-scoped cookie', { input: object({ link: string, request_id: requestId }, ['link', 'request_id']), security: [], 'x-input-error': 'invalid_link' }) } },
  { name: 'paymentEvents', path: '/v1/payment/events', methods: { post: op('paymentEvents', 'Receive Stripe events', object({ received: { const: true } }, ['received']), { input: object(), security: [], 'x-input-error': 'invalid_signature',
    description: 'For Stripe only: events signed with the endpoint secret (Stripe-Signature). Subscription changes set whether a principal pays.' }) } },
  { name: 'principalChallenges', path: '/v1/principals/challenges', methods: {
    post: op('beginPrincipal', 'Ask for the options a new passkey answers, to become a principal by it', object({ options: object() }, ['options']), { input: object({ kind: { const: 'webauthn' }, name: errorCode(string, 'invalid_name') }, ['kind']), security: [], 'x-input-error': 'invalid_kind', description: 'Returns WebAuthn creation options (PublicKeyCredentialCreationOptionsJSON). The name is the passkey\'s label; one is drawn when none is given.' }),
  } },
  { name: 'principals', path: '/v1/principals', methods: {
    post: op('createPrincipal', 'Make a principal of the caller\'s own, or become one', 'Became', { input: { anyOf: [ref('Become'), ref('BecomeComplete')] }, status: 201, security: [{}, ...secure], 'x-input-error': 'invalid_name',
      description: 'Anyone may become a principal, saying nothing of who they are. By a key: POST {kind: "key", name} makes the principal and shows its key once. By a passkey: POST /v1/principals/challenges {kind: "webauthn"} returns options; POST here with the credential made from them makes the principal, signed in. With a session or key, POST makes a principal the caller owns; it has no entry until one is added at /v1/principals/{id}/credentials. To ask someone for access, a principal uses POST /v1/requests with {"operations":[{"method":"POST","path":"/v1/principals/{its id}/relations","body":{"relation":"agent","object_type":"principal","object_id":"me"}}]} and gives them the returned verification_uri and user_code; GET /v1/principals/me reports acts_for afterward. The CLI performs the bootstrap: foundation init <server> --name <name> makes the principal, foundation join asks for approval.' }),
  } },
  { name: 'principal', group: 'principals', path: '/v1/principals/{principalId}', methods: {
    get: op('getPrincipal', 'Read a principal', one('Principal')), patch: op('renamePrincipal', 'Rename a principal', one('Principal'), { input: 'Rename', 'x-input-error': 'invalid_name' }), delete: okay('removePrincipal', 'Remove an owned principal, or oneself, and its resources'),
  } },
  { name: 'transferPrincipal', group: 'principals', path: '/v1/principals/{principalId}/transfer', methods: { post: op('transferPrincipal', 'Give an owned principal to another principal', one('Principal'), { input: 'Transfer', 'x-input-error': 'invalid_transfer', description: 'By its owner. The owner\'s record and alias move; the principal\'s own lines and keys stay.' }) } },
  { name: 'principalRelations', group: 'principals', path: '/v1/principals/{principalId}/relations', methods: {
    post: okay('addRelation', 'Draw a line from this principal to another principal or to a thing', { input: 'RelationInput', status: 201, 'x-input-error': 'invalid_relation', description: 'The principal in the path is the one the line is from: POST /v1/principals/{agent}/relations {relation: "agent", object_type: "principal", object_id: <owner>} makes it the owner\'s agent. Roles are agent, member and payer on principals and viewer/editor on things; a single action may be given as <action>_grant. The caller must be able to give it where the line ends. Ownership is not given here.' }),
    delete: okay('removeRelation', 'Remove a line from this principal', { input: 'RelationInput', 'x-input-error': 'invalid_relation', description: 'By the principal the line is from, or by whoever may share what it is onto.' }),
    get: op('listPrincipalRelations', 'List the lines a principal is at an end of', object({ relations: array(ref('Line')), next: { ...nullable(string), description: 'Pass as after to read the next page; null when there is none.' } }, ['relations', 'next']), {
    parameters: [query('relation', string, 'Only lines of this relation, such as owner, agent, member, payer, viewer.'), query('direction', choice(['from', 'to']), 'from: lines this principal drew toward others and their things. to: lines drawn toward it. Both when left out.'), query('principal', principalId, 'Only the lines between this principal and that one.'), query('limit', integer, 'How many to return: 1-200, 50 by default.'), query('after', string, 'The next value of the page before.')],
    description: 'For the principal itself, its members and its owner; one who only acts for it is not told whom it is joined to. Each line names who or what is at its other end, by id and name. One may be at the end of very many lines - an app owns a principal for each of its users - so they come a page at a time, oldest first. principalId may be me (the caller) or agent (the principal this server acts as).' }) } },
  { name: 'principalKey', group: 'principals', path: '/v1/principals/{principalId}/encryption-key', methods: {
    get: op('getKey', 'Read a principal\'s public key', object({ key: ref('PrincipalKey') }, ['key']), { description: 'For anyone who would seal for it. The principal itself is also given its private key wrapped per passkey.' }),
    put: op('publishKey', 'Publish the principal\'s public key, once', object({ key: ref('PrincipalKey') }, ['key']), { input: 'PublishKey', 'x-input-error': 'invalid_key', description: 'By the principal itself. A principal has one key; envelopes are made for it. Replacing it is refused (key_exists).' }),
  } },
  { name: 'principalCredentialChallenges', group: 'principals', path: '/v1/principals/{principalId}/credentials/challenges', methods: {
    post: op('beginCredential', 'Ask for what proves a new entry: options a passkey answers, or a link sent to an address', object({ options: object(), pending: ref('PendingSignin') }), { input: object({ kind: choice(['webauthn', 'email']), address: errorCode(string, 'invalid_email') }, ['kind']), status: [200, 202], 'x-input-error': 'invalid_kind', description: 'webauthn: returns creation options, answered by POST to the credentials. email: sends a single-use link to the address (202); opening it makes the address an entry.' }),
  } },
  { name: 'principalCredentials', group: 'principals', path: '/v1/principals/{principalId}/credentials', methods: {
    get: op('listCredentials', 'List the entries a principal is proven by: passkeys, addresses, keys', object({ credentials: array(ref('Credential')) }, ['credentials'])),
    post: op('addCredential', 'Add an entry to a principal: a passkey just made, or a key', object({ credential: ref('Credential'), token: string, backed_up: boolean }, ['credential']), { input: { anyOf: [object({ kind: { const: 'key' }, replaces: string }, ['kind']), ref('CompleteCredential')] }, status: 201, 'x-input-error': 'invalid_kind', description: 'key: issues a key, shown once as token; replaces names a key it takes the place of. webauthn: the RegistrationResponseJSON made from the challenge\'s options.' }),
  } },
  { name: 'principalCredential', group: 'principals', path: '/v1/principals/{principalId}/credentials/{credentialId}', methods: { delete: okay('removeCredential', 'Remove an entry of any kind; the sessions it proved end') } },
  { name: 'principalCredentialWrap', group: 'principals', path: '/v1/principals/{principalId}/credentials/{credentialId}/wrap', methods: { put: okay('keepWrap', 'Keep the principal\'s private key wrapped for this passkey', { input: object({ wrapped: string }, ['wrapped']), 'x-input-error': 'invalid_wrap' }) } },
  { name: 'links', group: 'principals', path: '/v1/principals/{principalId}/links', methods: { post: op('issueLink', 'Issue a one-use link for a store request', object({ link: object({ id, request_id: requestId, expires_at: time }, ['id', 'request_id', 'expires_at']), url: string, expires_at: time }, ['link', 'url', 'expires_at']), { input: object({ request_id: string }, ['request_id']), status: 201, 'x-input-error': 'invalid_request' }) } },
  { name: 'access', group: 'principals', path: '/v1/principals/{principalId}/access/{otherId}', methods: { delete: okay('revokeAccess', 'Take away another principal’s access to this one and to what it holds', { description: 'The principal in the path is the one whose things were reached; otherId is the one who loses the lines onto it and onto what it holds, and its open requests to it.' }) } },
  { name: 'mergeChallenges', group: 'principals', path: '/v1/principals/{principalId}/merges/challenges', methods: { post: op('mergeOptions', 'Start merging with another account: options its passkeys may answer', object({ options: object() }, ['options']), { input: object({ principal_id: principalId }, ['principal_id']), 'x-input-error': 'invalid_merge', description: 'The other account, by id. Only its passkeys may answer; an account with none is refused (no_passkey).' }) } },
  { name: 'merges', group: 'principals', path: '/v1/principals/{principalId}/merges', methods: { post: op('mergeBegin', 'Prove the other account by its passkey and learn what it has', 'MergeBegun', { input: object({ credential: object(), principal_id: principalId }, ['credential']), 'x-input-error': 'invalid_webauthn_credential', description: 'The passkey must be another principal\'s. Returns a ticket for completing, the other\'s key wrapped for that passkey (to open its secrets\' envelopes with what the passkey yields), and its secrets with their envelopes for it, so that they can be sealed anew for this principal.' }) } },
  { name: 'mergeComplete', group: 'principals', path: '/v1/principals/{principalId}/merges/{ticket}', methods: { post: op('mergeComplete', 'Make the two accounts one', 'MergeDone', { input: 'MergeComplete', 'x-input-error': 'invalid_merge', description: 'Everything the ending account owns, the principals it owns, its passkeys and addresses become the remaining one\'s; the ending one ends, with the lines it drew and was drawn, and its sessions. A name the remaining one already uses refuses the whole (name_taken).' }) } },
  { name: 'principalRecipients', group: 'principals', path: '/v1/principals/{principalId}/recipients', methods: { get: op('listRecipients', 'Whom a secret kept by the principal is sealed for', object({ recipients: array(ref('Recipient')) }, ['recipients']), { description: 'The principal, those who stand for it, and Foundation\'s principal when it is the principal\'s agent, each with a public key. Make an envelope for each when placing a secret.' }) } },
  { name: 'principalPaymentSessions', group: 'principals', path: '/v1/principals/{principalId}/payment/sessions', methods: { post: op('beginPayment', 'Start setting a payment method', object({ url: string }, ['url']), { input: 'Empty', description: 'Returns the address of Stripe\'s page for setting a payment method. Coming back, the page carries the session id to PUT here.' }) } },
  { name: 'principalPayment', group: 'principals', path: '/v1/principals/{principalId}/payment', methods: {
    get: op('getPayment', 'Read whether the principal pays for use beyond the free part', object({ payment: ref('Payment') }, ['payment'])),
    put: op('completePayment', 'Set the payment method the session at Stripe arranged', object({ payment: ref('Payment') }, ['payment']), { input: object({ session_id: string }, ['session_id']), 'x-input-error': 'invalid_payment' }),
  } },
  { name: 'principalUsage', group: 'principals', path: '/v1/principals/{principalId}/usage', methods: { get: op('getUsage', 'Read storage usage and limits', 'Usage') } },
  { name: 'principalAuditLog', group: 'principals', path: '/v1/principals/{principalId}/audit-log', methods: { get: op('getAuditLog', 'Read the principal’s audit records', many('entries', 'AuditEntry')) } },
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
    post: op('createRequest', 'Ask someone to make calls of this API that they may make and the caller may not', one('Request'), { input: 'CreateRequest', status: 201, 'x-input-error': 'invalid_operations', description: 'operations are calls of this API (1-8), as the one asked would send them: method, path (me in it is the one asked) and body; inputs leave places in body for the one asked to supply (a value only they have, a secret they type and seal). Any call they may make may be asked for, except those only they can make where they are (proving with their device, payment, merging, a consent flow already begun, issuing request links). The request goes to to, or else to whoever stands as the caller itself (as a person does for the account an app keeps for them). One nobody has taken on yet asks nobody, and may ask only for POST /v1/principals/{itself}/relations {relation: "agent", object_type: "principal", object_id: "me"}: whoever opens verification_uri and types the returned user_code (as in RFC 8628) answers, and owns it from then on. binding_message tells the one asked why. Poll GET /v1/requests/{requestId} no more often than interval seconds; faster polling is answered with slow_down, and an expired request with expired_token. results holds what each call answered. Do not collect secrets in chat.' }),
  } },
  { name: 'request', group: 'requests', path: '/v1/requests/{requestId}', methods: {
    get: op('getRequest', 'Read a request and its outcome', one('Request'), { security: [...secure, { requestLink: [] }] }),
    delete: op('cancelRequest', 'Cancel a sent request', one('Request'), { input: 'Empty' }),
  } },
  { name: 'grant', group: 'requests', path: '/v1/requests/{requestId}/grant', methods: { post: op('grantRequest', 'Answer a request by making the calls it asks for', object({ request: ref('Request'), continue: { ...object({ url: string }), description: 'Where a call goes on: a service\'s consent. The request is answered when it comes back.' } }, ['request']), { input: 'GrantRequest', security: [...secure, { requestLink: [] }], description: 'Request-link cookies may answer only their own request. Each call is handled as if the one answering had sent it, by the same rules.' }) } },
  { name: 'deny', group: 'requests', path: '/v1/requests/{requestId}/deny', methods: { post: op('denyRequest', 'Decline a received request', one('Request'), { input: 'Empty', security: [...secure, { requestLink: [] }] }) } },
  { name: 'environments', path: '/v1/principals/{principalId}/environments', methods: {
    post: op('createEnvironment', 'Open an execution environment', one('Environment'), { input: 'CreateEnvironment', status: 201, description: 'Requires a configured runner and available compute allowance. identity is an optional principal the environment may act as; granting it requires pass permission.' }),
  } },
  { name: 'runs', path: '/v1/principals/{principalId}/runs', methods: { post: op('run', 'Run one command on a lent machine, or send one HTTPS request', { anyOf: [object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command']), ref('FetchResult')] }, { input: 'Run', 'x-input-error': 'invalid_command', description: 'With command: closes the environment when the command exits. Waits up to 20 seconds; a running command returns 202 and can be polled by its id. With request: use bindings to place referenced values at JSON Pointer targets in headers or body. Ordinary strings are literal. json and form are encoded after binding; body is raw text or base64. URLs cannot be binding targets. Public HTTPS only, redirects are returned without following, request/response body limit 1 MiB. Bound values are redacted from the response. save stores the response body as a secret under that name and omits it from the response.', responses: { 200: response({ anyOf: [object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command']), ref('FetchResult')] }), 202: response(object({ environment: ref('Environment'), command: ref('Command') }, ['environment', 'command'])), default: response('Error', 'Failure') } }) } },
  { name: 'commands', group: 'resources', path: '/v1/resources/{resourceId}/commands', methods: { post: op('startCommand', 'Run a command in an environment', one('Command'), { input: 'CommandInput', 'x-input-error': 'invalid_command', responses: { 200: response(one('Command')), 202: response(one('Command'), 'Still running after 20 seconds; poll by command id.'), default: response('Error', 'Failure') } }) } },
  { name: 'command', group: 'resources', path: '/v1/resources/{resourceId}/commands/{commandId}', methods: { get: op('getCommand', 'Read command status and output', one('Command')) } },
  { name: 'invocations', group: 'resources', path: '/v1/resources/{resourceId}/invocations', methods: { post: op('invokeFunction', 'Call a function a principal keeps', 'FetchResult', { input: object({ arguments: { ...map(string), description: 'The arguments the function declares, by name. Each is text.' } }), 'x-input-error': 'invalid_arguments',
    description: 'Sends the request the function\'s owner decided, with the owner\'s connections and secrets and these arguments where the function puts them. The caller needs only to be let to call it (its owner\'s agent, or an invoker of it) and reaches none of what it uses; what it used is taken out of the answer.' }) } },
  { name: 'resources', path: '/v1/principals/{principalId}/resources', methods: {
    get: op('listResources', 'List a principal’s resources or find one by literal name', { anyOf: [many('resources', 'Resource'), one('Resource')] }, {
      parameters: [query('kind', choice(KINDS)), query('name', string, 'Exact name lookup for secret, object, service, app or function; returns resource (singular).'), query('prefix', string), query('service', string, 'Filter connections by service id.')],
      description: 'Connection metadata contains no renewable state or token. Apps may include the built-in Foundation app. Without name the result is resources (an array).' }),
    put: op('putResource', 'Create or replace a resource by kind and name', one('Resource'), { parameters: [query('kind', choice(['secret', 'object', 'app', 'service', 'function']), undefined, true), query('name', resourceName, undefined, true), header('If-Match', 'Secret revision from ETag; mismatch returns 412 secret_changed.'), header('If-None-Match', 'Use * to create a service only when its name is unused; otherwise 412 name_taken.')],
      description: 'kind determines the body: object stores raw bytes (including when Content-Type is application/json); secret, app and service parse JSON. A secret is placed sealed (SecretInput), 1 byte–1 MiB; objects allow up to 25 MiB and preserve Content-Type. Managed connections are created through /v1/principals/{principalId}/connections, not here.',
      requestBody: { required: true, content: { ...rawContent, 'application/json': { schema: { anyOf: [ref('SecretInput'), ref('ServiceDefinition'), ref('AppInput'), ref('FunctionDefinition')], description: 'SecretInput for kind=secret; ServiceDefinition for kind=service; AppInput for kind=app; FunctionDefinition for kind=function.' } } } },
      responses: { 200: { ...response(one('Resource')), headers: etag }, default: response('Error', 'Failure') },
    }),
  } },
  { name: 'resource', group: 'resources', path: '/v1/resources/{resourceId}', methods: {
    get: op('getResource', 'Read resource metadata', one('Resource')),
    put: op('replaceDefinition', 'Replace a service definition or what a function does', one('Resource'), { input: { anyOf: [ref('ServiceDefinition'), ref('FunctionDefinition')] }, 'x-input-error': 'invalid_definition' }),
    patch: op('patchResource', 'Rename a resource, update an app or service, or set an environment’s identity', one('Resource'), { input: 'PatchResource', description: 'For secret/object/connection, supply name. For an environment, supply identity to attach or detach the principal it runs as. For an app, top-level client fields may also be changed. For a service, name renames the resource and auth_schemes adds connection methods; only those two fields are accepted.' }),
    delete: op('removeResource', 'Remove a resource, disconnect a connection or close an environment', object({ ok: { const: true }, service_revoked: nullable(boolean), connections_stopped: integer }, ['ok']), { input: 'DeleteResource', description: 'For an environment: returns success only after the runner confirms removal. If it cannot yet confirm, returns 503 environment_stopping and retains the environment with access revoked; stopping and removal retry automatically, including after restart. For connections, revoke (boolean) is required: true also attempts service-side revocation. service_revoked is true/false when attempted, null otherwise. For an app in use, confirm:true is required; its connections stop working. Other kinds accept {}. Environments are closed before removal.' }),
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
  { name: 'confirmation', path: '/v1/principals/{principalId}/connections/confirmation', methods: {
    get: op('getConfirmation', 'Review changed service authorization', 'Confirmation', { parameters: [query('state', string, undefined, true)], security: session }),
    post: op('acceptConfirmation', 'Accept changed service authorization', one('Connection'), { input: state, security: session, 'x-input-error': 'invalid_state' }),
    delete: okay('cancelConfirmation', 'Cancel changed service authorization', { input: state, security: session, 'x-input-error': 'invalid_state' }),
  } },
  { name: 'connections', path: '/v1/principals/{principalId}/connections', methods: { post: op('connectService', 'Connect a service', 'ConnectResult', { input: 'Connect', responses: { 200: response('ConnectResult'), 201: response(one('Connection'), 'A token connection was made.'), default: response('Error', 'Failure') } }) } },
  { name: 'connectionComplete', path: '/v1/principals/{principalId}/connections/{state}', methods: { post: op('completeRole', 'Finish role-based service authorization', one('Connection'), { input: object({ fields: map(string) }), security: session, 'x-input-error': 'invalid_state', description: 'state is what starting the connection returned.' }) } },
  { name: 'oauthCallback', path: '/oauth/callback', methods: { get: op('oauthCallback', 'Return from service OAuth consent', 'Empty', { security: session, parameters: [query('state', string, undefined, true), query('code'), query('error')], responses: { 303: { description: 'Returns to the service page or original request, with a result code.', headers: { Location: { schema: string } } } } }) } },
  { name: 'injections', path: '/v1/principals/{principalId}/injections', methods: { post: op('inject', 'Obtain secret bytes or current service connections for a process', 'Injection', { input: 'Inject', 'x-input-error': 'invalid_names', description: 'Each input has exactly one of name (literal secret name) or id (secret/connection id). A secret requires as (a non-reserved environment variable). A connection without output delivers all its named values; output selects one. as can rename a single value. filename delivers base64 file bytes instead of environment text. Connections refresh if needed. Deliver values privately to the intended process; do not print them into chat or logs. CLI exec does this without exposing values to the agent.' }) } },
  { name: 'export', path: '/v1/principals/{principalId}/export', methods: { get: op('exportData', 'Download the owner’s data, including secret bytes', 'Export', { description: 'Secrets and connection states go out as kept: sealed, with their envelopes; they open with the owner\'s key where an envelope was made for them. Handle as private data.' }) } },
];

// A WebAuthn credential is known by the id its authenticator gave it (base64url, up to 1023 bytes).
const credentialId = { type: 'string', pattern: '^[A-Za-z0-9_-]{16,1364}$' };
const pathSchemas = { principalId, otherId: principalId, ticket: { type: 'string', pattern: '^[A-Za-z0-9_-]{16,128}$' }, state: { type: 'string', pattern: '^[A-Za-z0-9_-]{16,128}$' }, requestId, resourceId: id, keyId: id, commandId: id, credentialId };
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
  const selected = route?.name === 'resources' ? (variant === 'service' ? 'ServiceDefinition' : variant === 'app' ? 'AppInput' : variant === 'function' ? 'FunctionDefinition' : null)
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
