import { z } from 'zod';
import { SSHConnection, SSHSettings } from './ssh.js';
import { decodeProtectedHeader } from 'jose';
import { AwsConnectionInfo } from './aws.js';

if (typeof window !== 'undefined') z.config({ jitless: true });

export const Id = z.uuid();
export const Name = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .regex(/^[^\u0000-\u001f\u007f]+$/u);
export const Time = z.iso.datetime();
export const Json = z.json();
export type JsonValue = z.infer<typeof Json>;
export const JsonObject = z.record(z.string(), Json);
export const Locale = z.enum(['ja', 'en']);
export const Action = z.enum([
  'read',
  'create',
  'update',
  'delete',
  'share',
  'transfer',
  'reveal',
  'use',
  'execute',
  'manage_credentials',
  'manage_billing',
  'export',
]);
export type ActionName = z.infer<typeof Action>;
// The role that gives an action on its own, read "subject is the role of object". Which roles a type has is the
// authorization schema's.
export const RoleOf = {
  read: 'reader',
  create: 'creator',
  update: 'editor',
  delete: 'deleter',
  share: 'sharer',
  transfer: 'transferrer',
  reveal: 'revealer',
  use: 'user',
  execute: 'runner',
  manage_credentials: 'credential_manager',
  manage_billing: 'billing_manager',
  export: 'exporter',
} as const satisfies Record<ActionName, string>;
export const ResourceKind = z.enum([
  'variable',
  'connection',
  'service',
  'method',
  'app',
  'object',
  'environment',
  'function',
]);
export type ResourceKindName = z.infer<typeof ResourceKind>;
export const PublicKey = z
  .object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: z.string().min(40).max(50),
    y: z.string().min(40).max(50),
  })
  .strict();
export type PublicEncryptionKey = z.infer<typeof PublicKey>;
const WrappedKeyHeader = z.object({ alg: z.literal('dir'), enc: z.literal('A256GCM'), sub: Id }).strict();
export const WrappedKey = z.string().max(16384)
  .regex(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/)
  .refine(value => {
    try {
      return WrappedKeyHeader.safeParse(decodeProtectedHeader(value)).success;
    } catch {
      return false;
    }
  }, 'Use an A256GCM JWE for the wrapped encryption key.')
  .brand<'WrappedEncryptionKey'>();
export type WrappedEncryptionKey = z.infer<typeof WrappedKey>;
export const Sealed = z
  .object({
    protected: z.string().max(2048),
    iv: z.string().max(64),
    ciphertext: z.string().max(2_000_000),
    tag: z.string().max(64),
    aad: z.string().max(2048).optional(),
    recipients: z
      .array(
        z.object({
          encrypted_key: z.string().max(2048),
          header: z.object({ kid: Id, epk: PublicKey.optional(), alg: z.string().optional() }).passthrough(),
        }),
      )
      .min(1)
      .max(100),
  })
  .strict();
export type SealedContent = z.infer<typeof Sealed>;
export const Recipient = z.object({ id: Id, name: Name, publicKey: PublicKey });

export const Principal = z.object({
  id: Id,
  name: Name,
  // Whom this principal belongs to, if anyone: its owner acts as it.
  owner: z.object({ id: Id, name: Name }).nullable(),
  createdAt: Time,
  permissions: z.array(Action),
  createKinds: z.array(ResourceKind),
  publicKey: PublicKey.nullable(),
});
export type PrincipalView = z.infer<typeof Principal>;
export const Credential = z.object({
  id: Id,
  kind: z.enum(['passkey', 'email', 'key']),
  name: z.string(),
  createdAt: Time,
  lastUsedAt: Time.nullable(),
  expiresAt: Time.nullable(),
  // Whether this way in carries the principal's wrapped encryption key, so it can open encrypted values.
  canOpen: z.boolean(),
});
// A line: the subject is the relation of the object ("the AI is the agent of its person"). The object is a principal
// or a thing; the relation is a role its type declares in the authorization schema.
export const RelationName = z.string().regex(/^[a-z][a-z_]*[a-z]$/).max(64);
export const RelationInput = z.object({ subjectId: Id, relation: RelationName, objectId: Id }).strict();
export const Relation = RelationInput.extend({
  objectType: z.enum(['principal', ...ResourceKind.options]),
  subjectName: Name,
  objectName: Name,
  createdAt: Time,
});
export const ApiError = z.object({
  error: z.object({ code: z.string(), message: z.string(), details: Json.optional() }),
});
export const Ok = z.object({ ok: z.literal(true) });

const Field = z.object({
  name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/),
  label: z.string(),
  secret: z.boolean().optional(),
  required: z.boolean().optional(),
  placeholder: z.string().optional(),
  note: z.string().optional(),
  pattern: z.string().optional(),
});
const OutputMap = z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.string());
const Scopes = z.object({
  values: z
    .array(z.object({ id: z.string(), name: z.string(), description: z.string().optional() }))
    .optional(),
  default: z.array(z.string()).default([]),
  required: z.array(z.string()).optional(),
  separator: z.string().default(' '),
  docs: z.url().optional(),
});
const UrlTemplate = z.string().min(1).max(4096);
const PointerList = z.union([z.string(), z.array(z.string()).min(1)]);
export const OAuthDefinition = z.object({
  application: z.enum(['required', 'implicit']).default('required'),
  grantType: z.enum(['authorization_code', 'client_credentials']).optional(),
  issuer: z.url().optional(),
  authorizeUrl: UrlTemplate.optional(),
  tokenUrl: UrlTemplate,
  identity: z
    .object({
      url: UrlTemplate.optional(),
      from: z.enum(['token', 'app']).optional(),
      method: z.enum(['GET', 'POST']).default('GET'),
      id: PointerList.default('/id'),
      name: PointerList.default('/name'),
      headers: z.record(z.string(), z.string()).default({}),
    })
    .optional(),
  revoke: z
    .object({
      url: UrlTemplate,
      style: z.enum(['rfc7009', 'bearer', 'github', 'delete']).default('rfc7009'),
      auth: z.enum(['body', 'basic', 'none']).optional(),
    })
    .optional(),
  clientAuth: z.enum(['body', 'basic', 'none']).default('body'),
  pkce: z.boolean().default(true),
  tokenFormat: z.enum(['form', 'json']).default('form'),
  okPointer: z.string().optional(),
  authorizeParams: z.record(z.string(), z.string()).default({}),
  tokenParams: z.record(z.string(), z.string()).default({}),
  defaults: z.record(z.string(), z.string()).default({}),
  scopes: Scopes.default({ default: [], separator: ' ' }),
  fields: z.array(Field).default([]),
  outputs: OutputMap.default({ ACCESS_TOKEN: '/accessToken' }),
  adapter: z.string().regex(/^[a-z][a-z0-9_-]{0,99}$/).optional(),
  keep: z.array(z.string()).default([]),
  hint: z.string().optional(),
}).refine(value => value.grantType === 'client_credentials' || Boolean(value.authorizeUrl), {
  path: ['authorizeUrl'], message: 'An authorization code flow requires an authorization URL.',
});
export const TokenDefinition = z.object({
  fields: z.array(Field).min(1),
  outputs: OutputMap,
  console: z.url().optional(),
  instructions: z.string().optional(),
  hint: z.string().optional(),
});
export const AuthKind = z.enum(['oauth', 'token', 'aws']);
export type AuthKindName = z.infer<typeof AuthKind>;
export const AwsDefinition = z.object({ hint: z.string().optional() }).strict();
const methodMetadata = {
  name: Name,
  docs: z.url().optional(),
  console: z.url().optional(),
};
const OAuthMethod = z
  .object({ ...methodMetadata, kind: z.literal('oauth'), config: OAuthDefinition })
  .strict();
const TokenMethod = z
  .object({ ...methodMetadata, kind: z.literal('token'), config: TokenDefinition })
  .strict();
const AwsMethod = z.object({ ...methodMetadata, kind: z.literal('aws'), config: AwsDefinition }).strict();
export const MethodDefinition = z.discriminatedUnion('kind', [OAuthMethod, TokenMethod, AwsMethod]);
export type MethodDescription = z.infer<typeof MethodDefinition>;
const methodCatalogMetadata = {
  id: z.string().min(1),
  builtin: z.boolean(),
  availability: z.enum(['ready', 'app-required', 'unavailable']),
};
export const CatalogMethod = z.discriminatedUnion('kind', [
  OAuthMethod.extend(methodCatalogMetadata),
  TokenMethod.extend(methodCatalogMetadata),
  AwsMethod.extend(methodCatalogMetadata),
]);
export type CatalogConnectionMethod = z.infer<typeof CatalogMethod>;
export const MethodKey = z.string().regex(/^[a-z][a-z0-9_-]{0,79}$/);
export const ServiceMetadata = z
  .object({
    name: Name,
    logo: z
      .string()
      .regex(/^[a-z0-9-]+$/)
      .optional(),
    api: z.url().optional(),
    docs: z.url().optional(),
    console: z.url().optional(),
  })
  .strict();
export const ServiceDefinition = ServiceMetadata.extend({
  methods: z.record(MethodKey, z.string().min(1)),
}).strict();
export const ServiceInputDefinition = ServiceMetadata.extend({
  methods: z.record(MethodKey, z.union([z.string().min(1), MethodDefinition])),
}).strict();
export type ServiceDefinitionInput = z.infer<typeof ServiceInputDefinition>;
export type ServiceDescription = z.infer<typeof ServiceDefinition>;
export const CatalogEntry = ServiceMetadata.extend({
  id: z.string(),
  builtin: z.boolean(),
  methods: z.record(MethodKey, CatalogMethod),
});
export type CatalogService = z.infer<typeof CatalogEntry>;

// An input names its item by id. A connection also names which of its outputs to use.
export const Source = z.object({ id: Id, output: z.string().min(1).max(100).optional() }).strict();
export type SourceReference = z.infer<typeof Source>;
export const Input = z
  .object({
    name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
    source: Source,
    format: z.enum(['text', 'file', 'json']).default('text'),
    pointer: z.string().optional(),
  })
  .strict();
export type InjectionInput = z.infer<typeof Input>;
export const Binding = z
  .object({
    pointer: z.string().max(500),
    parts: z
      .array(z.union([z.string().max(8192), Source]))
      .min(1)
      .max(32),
  })
  .strict();
export const HttpRequest = z
  .object({
    url: z.string().max(4096),
    method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
    headers: z.record(z.string(), z.string().max(8192)).default({}),
    body: z.string().max(1_000_000).optional(),
    json: Json.optional(),
    form: z.record(z.string(), z.string()).optional(),
    bindings: z.array(Binding).max(32).default([]),
  })
  .strict();
export type HttpRequestInput = z.infer<typeof HttpRequest>;
export const FunctionDefinition = z
  .object({
    description: z.string().max(2000).default(''),
    request: HttpRequest,
    parameters: z
      .array(
        z.object({
          name: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*$/),
          label: z.string().max(100),
          required: z.boolean().default(true),
          default: z.string().optional(),
        }),
      )
      .max(32)
      .default([]),
    save: z.record(z.string(), Name).default({}),
    outputOwnerId: Id.optional(),
  })
  .strict();
export type FunctionSpec = z.infer<typeof FunctionDefinition>;

const resourceBase = {
  id: Id,
  ownerId: Id,
  name: Name,
  createdAt: Time,
  updatedAt: Time,
  version: z.number().int().positive(),
  permissions: z.array(Action),
};
export const EnvironmentState = z.enum(['starting', 'running', 'stopping', 'stopped', 'failed']);
export const EnvironmentDeletion = z.object({
  state: z.enum(['pending', 'failed', 'complete']),
  error: z.string().nullable(),
});
export const Lifetime = z
  .object({
    idleSeconds: z.number().int().min(60).max(86400).default(3600),
    maxSeconds: z.number().int().min(60).max(86400).default(3600),
  })
  .strict();
export const EnvironmentInput = z
  .object({
    image: z.string().min(1).max(300).optional(),
    size: z.enum(['small', 'medium', 'large']).default('small'),
    lifetime: Lifetime.default({ idleSeconds: 3600, maxSeconds: 3600 }),
    ssh: SSHSettings.optional(),
  })
  .strict();
export type EnvironmentOptions = z.infer<typeof EnvironmentInput>;
const custodyMetadata = {
  recipients: z.array(Id).default([]), executors: z.array(Id).default([]),
  custodyRevision: z.number().int().positive().nullable().default(null),
};
export const VariableResource = z.object({
  ...resourceBase,
  kind: z.literal('variable'),
  data: z.object({ ...custodyMetadata, bytes: z.number().int().nonnegative() }),
});
export const ConnectionResource = z.object({
  ...resourceBase,
  kind: z.literal('connection'),
  data: z.object({
    ...custodyMetadata,
    methodId: z.string(),
    methodName: z.string(),
    methodKind: AuthKind,
    services: z.array(z.object({ id: z.string(), name: Name })).default([]),
    account: z.string(),
    accountId: z.string().nullable().default(null),
    accountVerified: z.boolean().default(false),
    scopes: z.array(z.string()),
    scopesStatus: z.enum(['unknown', 'requested', 'reported']).default('unknown'),
    outputs: z.array(z.string()),
    state: z.enum(['ready', 'reconnect', 'review', 'disconnecting', 'uncertain']),
    appId: Id.nullable(),
    generation: Id.optional(),
    authorizationDigest: z.string().optional(),
    aws: AwsConnectionInfo.optional(),
  }),
});
export const ServiceResource = z.object({
  ...resourceBase,
  kind: z.literal('service'),
  data: ServiceDefinition,
});
export const MethodResource = z.object({
  ...resourceBase,
  kind: z.literal('method'),
  data: MethodDefinition,
});
export const AppResource = z.object({
  ...resourceBase,
  kind: z.literal('app'),
  data: z.object({ ...custodyMetadata, methodId: z.string(), clientId: z.string(),
    fields: z.record(z.string(), z.string()).default({}), generation: Id.optional() }),
});
export const ObjectResource = z.object({
  ...resourceBase,
  kind: z.literal('object'),
  data: z.object({ size: z.number().int().nonnegative(), contentType: z.string() }),
});
export const EnvironmentResource = z.object({
  ...resourceBase,
  kind: z.literal('environment'),
  data: EnvironmentInput.extend({
    executorId: Id.optional(), operatorId: Id.optional(), driver: z.enum(['attached', 'managed']).optional(),
    capabilities: z.array(z.string()).optional(), isolation: z.enum(['process', 'container']).optional(),
    manifestDigest: z.string().optional(),
    processes: z.object({ workingDirectory: z.string() }).optional(),
    ssh: SSHConnection.optional(),
    awsPrincipal: z.string().optional(),
    state: EnvironmentState,
    deletion: EnvironmentDeletion.optional(),
    startedAt: Time.nullable(),
    stoppedAt: Time.nullable(),
    lastActiveAt: Time,
    error: z.string().nullable(),
  }),
});
export const FunctionResource = z.object({
  ...resourceBase,
  kind: z.literal('function'),
  data: FunctionDefinition,
});
export const Resource = z.discriminatedUnion('kind', [
  VariableResource,
  ConnectionResource,
  ServiceResource,
  MethodResource,
  AppResource,
  ObjectResource,
  EnvironmentResource,
  FunctionResource,
]);
export type ResourceView = z.infer<typeof Resource>;
export type VariableView = z.infer<typeof VariableResource>;
export type ConnectionView = z.infer<typeof ConnectionResource>;
export type EnvironmentView = z.infer<typeof EnvironmentResource>;
export type ObjectView = z.infer<typeof ObjectResource>;
export const NewResource = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('service'), name: Name, definition: ServiceInputDefinition }).strict(),
  z.object({ kind: z.literal('method'), name: Name, definition: MethodDefinition }).strict(),
  z.object({ kind: z.literal('environment'), name: Name.optional(), options: EnvironmentInput }).strict(),
  z.object({ kind: z.literal('function'), name: Name, definition: FunctionDefinition }).strict(),
]);
export type NewResourceInput = z.infer<typeof NewResource>;
export const UpdateResource = z
  .object({
    version: z.number().int().positive(),
    name: Name.optional(),
    definition: z.union([ServiceInputDefinition, MethodDefinition, FunctionDefinition]).optional(),
  })
  .strict();

export const Command = z
  .object({
    command: z.array(z.string().max(8192)).min(1).max(100),
    stdin: z.string().max(1_000_000).optional(),
    timeoutSeconds: z.number().int().min(1).max(3600).default(60),
    inputs: z.array(Input).max(32).default([]),
  })
  .strict();
export const Operation = z
  .object({
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT']),
    path: z.string().startsWith('/api/').max(2048),
    body: Json.optional(),
    inputs: z
      .array(
        z.object({
          pointer: z.string(),
          label: z.string().min(1).max(100),
          secret: z.boolean().default(false),
          multiline: z.boolean().default(false),
          site: z.url().optional(),
        }),
      )
      .max(16)
      .default([]),
  })
  .strict();
export type RequestedOperation = z.infer<typeof Operation>;
// What an operation does, in the words shown to the one asked to approve it: Japanese and English.
export const OperationTitle = z.object({ ja: z.string(), en: z.string() }).strict();
export type OperationTitle = z.infer<typeof OperationTitle>;
export const ConnectionRequest = z.object({ ownerId: z.union([Id, z.literal('$approver')]),
  methodId: z.string().min(1).max(200), connectionId: Id.optional(), environmentId: Id.optional(), name: Name.optional() }).strict();
export const RequestInput = z
  .object({
    to: Id.optional(),
    message: z.string().max(1000).default(''),
    operations: z.array(Operation).min(1).max(8),
    expiresInMinutes: z.number().int().min(1).max(1440).default(30),
  })
  .strict();
const Named = z.object({ id: Id, name: Name });
// A change its requester has made its own side of, waiting on the side the request is sent to: a line that needs both
// its ends, or something passed to a new owner. The requester makes it once that side agrees.
export const Proposal = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('line'), subject: Named, relation: RelationName, object: Named }),
  z.object({ kind: z.literal('transfer'), item: Named, to: Named }),
]);
export const ApprovalRequest = z.object({
  id: Id,
  from: Principal.pick({ id: true, name: true }),
  to: Principal.pick({ id: true, name: true }).nullable(),
  message: z.string(),
  proposal: Proposal.nullable(),
  operations: z.array(Operation.extend({ title: OperationTitle })),
  state: z.enum(['pending', 'running', 'approved', 'declined', 'cancelled', 'expired']),
  results: z.array(Json.nullable()),
  createdAt: Time,
  expiresAt: Time,
  url: z.url(),
  code: z.string().optional(),
  continueUrl: z.url().nullable(),
  returnUrl: z.url().nullable(),
  refreshUrl: z.url().nullable(),
  canRespond: z.boolean(),
});
export type ApprovalView = z.infer<typeof ApprovalRequest>;
export const DeviceRequest = z.object({
  id: Id,
  name: Name,
  publicKey: PublicKey,
  state: z.enum(['pending', 'approving', 'approved']),
  principalId: Id.nullable(),
  createdAt: Time,
  expiresAt: Time,
});
export type DeviceView = z.infer<typeof DeviceRequest>;
export const Payment = z.object({
  available: z.boolean(),
  required: z.boolean(),
  active: z.boolean(),
  payer: Principal.pick({ id: true, name: true }).nullable(),
});
export const Usage = z.object({
  storageBytes: z.number().nonnegative(),
  storageLimit: z.number().positive(),
  computeSeconds: z.number().nonnegative(),
  computeLimit: z.number().positive(),
  month: z.string(),
});
export const AuditEntry = z.object({
  id: z.string(),
  actorId: Id.nullable(),
  action: z.string(),
  targetId: Id.nullable(),
  createdAt: Time,
  details: JsonObject,
});
export const Settings = z
  .object({ returnUrl: z.url().optional(), refreshUrl: z.url().optional() })
  .strict();
export const listOf = <T extends z.ZodType>(schema: T) =>
  z.object({ items: z.array(schema), next: z.string().nullable().default(null) });
export const IdParams = z.object({ id: Id });
export const OwnerParams = z.object({ owner: Id });
export const PageQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(100),
  after: z.string().optional(),
});
export const RelationQuery = PageQuery.extend({ object: Id.optional(), subject: Id.optional() })
  .refine((query) => Boolean(query.object) !== Boolean(query.subject), 'Choose the object or the subject of the lines.');
