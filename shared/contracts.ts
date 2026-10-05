import { z } from 'zod';

if (typeof window !== 'undefined') z.config({ jitless: true });

export const Id = z.uuid();
export const Name = z.string().trim().min(1).max(200).regex(/^[^\u0000-\u001f\u007f]+$/u);
export const Time = z.iso.datetime();
export const Json = z.json();
export type JsonValue = z.infer<typeof Json>;
export const JsonObject = z.record(z.string(), Json);
export const Locale = z.enum(['ja', 'en']);
export const Action = z.enum(['read', 'create', 'update', 'delete', 'share', 'transfer', 'reveal', 'use', 'execute', 'credentials', 'billing', 'export']);
export type ActionName = z.infer<typeof Action>;
export const ResourceKind = z.enum(['secret', 'connection', 'service', 'app', 'object', 'environment', 'function']);
export type ResourceKindName = z.infer<typeof ResourceKind>;
export const PublicKey = z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string().min(40).max(50), y: z.string().min(40).max(50) }).strict();
export type PublicEncryptionKey = z.infer<typeof PublicKey>;
export const Sealed = z.object({
  protected: z.string().max(2048), iv: z.string().max(64), ciphertext: z.string().max(2_000_000), tag: z.string().max(64),
  aad: z.string().max(2048).optional(),
  recipients: z.array(z.object({ encrypted_key: z.string().max(2048), header: z.object({ kid: Id, epk: PublicKey.optional(), alg: z.string().optional() }).passthrough() })).min(1).max(100),
}).strict();
export type SealedContent = z.infer<typeof Sealed>;
export const Recipient = z.object({ id: Id, name: Name, publicKey: PublicKey });

export const Principal = z.object({ id: Id, name: Name, createdAt: Time, permissions: z.array(Action), createKinds: z.array(ResourceKind), publicKey: PublicKey.nullable() });
export type PrincipalView = z.infer<typeof Principal>;
export const Credential = z.object({ id: Id, kind: z.enum(['passkey', 'email', 'key']), name: z.string(), createdAt: Time, lastUsedAt: Time.nullable(), expiresAt: Time.nullable() });
export const RelationInput = z.object({ subjectId: Id, relation: z.enum(['agent', 'member', 'payer']), principalId: Id }).strict();
export const Relation = RelationInput.extend({ id: Id, createdAt: Time, subjectName: Name, principalName: Name }).extend({ relation: z.enum(['owner', 'agent', 'member', 'payer']) });
export const Grant = z.object({ principalId: Id, actions: z.array(Action).min(1), principalName: Name.optional() });
export const ApiError = z.object({ error: z.object({ code: z.string(), message: z.string(), details: Json.optional() }) });
export const Ok = z.object({ ok: z.literal(true) });

const Field = z.object({ name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/), label: z.string(), secret: z.boolean().optional(), required: z.boolean().optional(), placeholder: z.string().optional(), note: z.string().optional(), pattern: z.string().optional() });
const OutputMap = z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.string());
const Scopes = z.object({ values: z.array(z.object({ id: z.string(), name: z.string(), description: z.string().optional() })).optional(), default: z.array(z.string()).default([]), separator: z.string().default(' '), docs: z.url().optional() });
const UrlTemplate = z.string().min(1).max(4096);
const PointerList = z.union([z.string(), z.array(z.string()).min(1)]);
export const OAuthDefinition = z.object({
  authorizeUrl: UrlTemplate, tokenUrl: UrlTemplate,
  identity: z.object({ url: UrlTemplate.optional(), from: z.enum(['token','app']).optional(), method: z.enum(['GET','POST']).default('GET'), id: PointerList.default('/id'), name: PointerList.default('/name'), headers: z.record(z.string(),z.string()).default({}) }).optional(),
  revoke: z.object({ url: UrlTemplate, style: z.enum(['rfc7009','bearer','github','delete']).default('rfc7009'), auth: z.enum(['body','basic','none']).optional() }).optional(),
  clientAuth: z.enum(['body', 'basic', 'none']).default('body'), pkce: z.boolean().default(true),
  tokenFormat: z.enum(['form','json']).default('form'), okPointer: z.string().optional(),
  authorizeParams: z.record(z.string(), z.string()).default({}), tokenParams: z.record(z.string(), z.string()).default({}),
  defaults: z.record(z.string(),z.string()).default({}),
  scopes: Scopes.default({ default: [], separator: ' ' }),
  fields: z.array(Field).default([]), outputs: OutputMap.default({ ACCESS_TOKEN: '/accessToken' }),
  adapter: z.enum(['google', 'github', 'ebay', 'openrouter', 'cloudflare', 'slack']).optional(),
  keep: z.array(z.string()).default([]), hint: z.string().optional(),
});
export const TokenDefinition = z.object({ fields: z.array(Field).min(1), outputs: OutputMap, console: z.url().optional(), instructions: z.string().optional(), hint: z.string().optional() });
export const ServiceDefinition = z.object({
  name: Name, logo: z.string().regex(/^[a-z0-9-]+$/).optional(), api: z.url().optional(), docs: z.url().optional(), console: z.url().optional(),
  auth: z.object({ oauth: OAuthDefinition.optional(), token: TokenDefinition.optional(), role: z.object({ kind: z.literal('aws'), hint: z.string().optional() }).optional() }).strict(),
}).strict();
export type ServiceDescription = z.infer<typeof ServiceDefinition>;
export const CatalogEntry = ServiceDefinition.extend({ id: z.string(), builtin: z.boolean(), available: z.array(z.enum(['oauth', 'token', 'role'])) });
export type CatalogService = z.infer<typeof CatalogEntry>;

export const Source = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('secret'), id: Id }).strict(),
  z.object({ kind: z.literal('connection'), id: Id, output: z.string().min(1).max(100) }).strict(),
]);
export type SourceReference = z.infer<typeof Source>;
export const Input = z.object({ name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/), source: Source, format: z.enum(['text', 'file', 'json']).default('text'), pointer: z.string().optional() }).strict();
export type InjectionInput = z.infer<typeof Input>;
export const Binding = z.object({ pointer: z.string().max(500), parts: z.array(z.union([z.string().max(8192), Source])).min(1).max(32) }).strict();
export const HttpRequest = z.object({
  url: z.string().max(4096), method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
  headers: z.record(z.string(), z.string().max(8192)).default({}), body: z.string().max(1_000_000).optional(),
  json: Json.optional(), form: z.record(z.string(), z.string()).optional(), bindings: z.array(Binding).max(32).default([]),
}).strict();
export type HttpRequestInput = z.infer<typeof HttpRequest>;
export const FunctionDefinition = z.object({
  description: z.string().max(2000).default(''), request: HttpRequest,
  parameters: z.array(z.object({ name: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*$/), label: z.string().max(100), required: z.boolean().default(true), default: z.string().optional() })).max(32).default([]),
  save: z.record(z.string(), Name).default({}),
}).strict();
export type FunctionSpec = z.infer<typeof FunctionDefinition>;

const resourceBase = { id: Id, ownerId: Id, name: Name, createdAt: Time, updatedAt: Time, version: z.number().int().positive(), permissions: z.array(Action) };
export const EnvironmentState = z.enum(['starting', 'running', 'stopping', 'stopped', 'failed']);
export const Lifetime = z.object({ idleSeconds: z.number().int().min(60).max(86400).default(3600), maxSeconds: z.number().int().min(60).max(86400).default(3600) }).strict();
export const EnvironmentInput = z.object({ image: z.string().min(1).max(300).optional(), size: z.enum(['small', 'medium', 'large']).default('small'), lifetime: Lifetime.default({ idleSeconds: 3600, maxSeconds: 3600 }), identityId: Id.nullable().default(null) }).strict();
export type EnvironmentOptions = z.infer<typeof EnvironmentInput>;
export const SecretResource = z.object({ ...resourceBase, kind: z.literal('secret'), data: z.object({ bytes: z.number().int().nonnegative(), recipients: z.array(Id), allowUse:z.boolean() }) });
export const ConnectionResource = z.object({ ...resourceBase, kind: z.literal('connection'), data: z.object({ serviceId: z.string(), scheme: z.enum(['oauth', 'token', 'role']), account: z.string(), scopes: z.array(z.string()), outputs: z.array(z.string()), state: z.enum(['ready', 'reconnect', 'review', 'disconnecting']), appId: Id.nullable() }) });
export const ServiceResource = z.object({ ...resourceBase, kind: z.literal('service'), data: ServiceDefinition });
export const AppResource = z.object({ ...resourceBase, kind: z.literal('app'), data: z.object({ serviceId: z.string(), clientId: z.string(), fields: z.record(z.string(), z.string()) }) });
export const ObjectResource = z.object({ ...resourceBase, kind: z.literal('object'), data: z.object({ size: z.number().int().nonnegative(), contentType: z.string() }) });
export const EnvironmentResource = z.object({ ...resourceBase, kind: z.literal('environment'), data: EnvironmentInput.extend({ state: EnvironmentState, startedAt: Time.nullable(), stoppedAt: Time.nullable(), lastActiveAt: Time, error: z.string().nullable() }) });
export const FunctionResource = z.object({ ...resourceBase, kind: z.literal('function'), data: FunctionDefinition });
export const Resource = z.discriminatedUnion('kind', [SecretResource, ConnectionResource, ServiceResource, AppResource, ObjectResource, EnvironmentResource, FunctionResource]);
export type ResourceView = z.infer<typeof Resource>;
export type SecretView = z.infer<typeof SecretResource>;
export type ConnectionView = z.infer<typeof ConnectionResource>;
export type EnvironmentView = z.infer<typeof EnvironmentResource>;
export type ObjectView = z.infer<typeof ObjectResource>;
export const NewResource = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('secret'), id: Id, name: Name, sealed: Sealed, bytes: z.number().int().min(0).max(1_000_000), allowUse: z.boolean().default(false) }).strict(),
  z.object({ kind: z.literal('service'), name: Name, definition: ServiceDefinition }).strict(),
  z.object({ kind: z.literal('app'), name: Name, serviceId: z.string(), clientId: z.string().min(1), clientSecret: z.string().optional(), fields: z.record(z.string(), z.string()).default({}) }).strict(),
  z.object({ kind: z.literal('environment'), name: Name.optional(), options: EnvironmentInput }).strict(),
  z.object({ kind: z.literal('function'), name: Name, definition: FunctionDefinition }).strict(),
]);
export type NewResourceInput = z.infer<typeof NewResource>;
export const UpdateResource = z.object({ version: z.number().int().positive(), name: Name.optional(), sealed: Sealed.optional(), bytes: z.number().int().nonnegative().max(1_000_000).optional(), allowUse:z.boolean().optional(), definition: z.union([ServiceDefinition, FunctionDefinition]).optional(), clientId: z.string().optional(), clientSecret: z.string().optional(), fields: z.record(z.string(), z.string()).optional() }).strict();

export const RunState = z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled']);
export const Command = z.object({ command: z.array(z.string().max(8192)).min(1).max(100), stdin: z.string().max(1_000_000).optional(), timeoutSeconds: z.number().int().min(1).max(3600).default(60), inputs: z.array(Input).max(32).default([]) }).strict();
export const RunInput = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest, save: z.record(z.string(), Name).default({}) }).strict(),
  z.object({ kind: z.literal('command'), environmentId: Id, ...Command.shape }).strict(),
  z.object({ kind: z.literal('function'), functionId: Id, arguments: z.record(z.string(), z.string()).default({}) }).strict(),
]);
export type NewRun = z.infer<typeof RunInput>;
export const Run = z.object({ id: Id, ownerId: Id, actorId: Id, kind: z.enum(['http', 'command', 'function']), resourceId: Id.nullable(), state: RunState, createdAt: Time, startedAt: Time.nullable(), finishedAt: Time.nullable(), result: Json.nullable(), error: z.string().nullable() });
export type RunView = z.infer<typeof Run>;
export const Operation = z.object({ method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']), path: z.string().startsWith('/api/').max(2048), body: Json.optional(), inputs: z.array(z.object({ pointer: z.string(), label: z.string().min(1).max(100), secret: z.boolean().default(false), multiline: z.boolean().default(false), site: z.url().optional() })).max(16).default([]) }).strict();
export type RequestedOperation = z.infer<typeof Operation>;
export const RequestInput = z.object({ to: Id.optional(), message: z.string().max(1000).default(''), operations: z.array(Operation).min(1).max(8), expiresInMinutes: z.number().int().min(1).max(1440).default(30) }).strict();
export const ApprovalRequest = z.object({ id: Id, from: Principal.pick({ id: true, name: true }), to: Principal.pick({ id: true, name: true }).nullable(), message: z.string(), operations: z.array(Operation), state: z.enum(['pending', 'running', 'approved', 'declined', 'cancelled', 'expired']), results: z.array(Json.nullable()), createdAt: Time, expiresAt: Time, url: z.url(), code: z.string().optional(), continueUrl:z.url().nullable(), returnUrl:z.url().nullable(), refreshUrl:z.url().nullable(), canRespond:z.boolean() });
export type ApprovalView = z.infer<typeof ApprovalRequest>;
export const Payment = z.object({ available: z.boolean(), active: z.boolean(), payer: Principal.pick({ id: true, name: true }).nullable() });
export const Usage = z.object({ storageBytes: z.number().nonnegative(), storageLimit: z.number().positive(), computeSeconds: z.number().nonnegative(), computeLimit: z.number().positive(), month: z.string() });
export const AuditEntry = z.object({ id: z.string(), actorId: Id.nullable(), action: z.string(), targetId: Id.nullable(), createdAt: Time, details: JsonObject });
export const ConnectionInput = z.object({ serviceId: z.string().min(1), scheme: z.enum(['oauth', 'token', 'role']), name: Name.optional(), connectionId: Id.optional(), appId: z.union([Id, z.literal('foundation')]).default('foundation'), scopes: z.array(z.string()).max(200).optional(), fields: z.record(z.string(), z.union([z.string(), Source])).default({}), returnTo: z.string().startsWith('/').default('/services') }).strict();
export type ConnectInput = z.infer<typeof ConnectionInput>;
export const Settings = z.object({ returnUrl: z.url().optional(), refreshUrl: z.url().optional(), webhookUrl: z.url().optional() }).strict();
export const listOf = <T extends z.ZodType>(schema: T) => z.object({ items: z.array(schema), next: z.string().nullable().default(null) });
export const IdParams = z.object({ id: Id });
export const OwnerParams = z.object({ owner: Id });
export const PageQuery = z.object({ limit: z.coerce.number().int().min(1).max(200).default(100), after: z.string().optional() });

export const KeyUpdate = z.object({ version: z.number().int().positive(), sealed: Sealed });
export const KeyUpdates = z.record(Id, KeyUpdate);
export const KeySharingItem = z.object({ id: Id, name: Name, version: z.number().int().positive(), sealed: Sealed, recipients: z.array(Recipient) });
