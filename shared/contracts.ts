import { z } from 'zod';
import { AuthorizedKeysFile, SSHAddress, SSHFingerprint, SSHPublicKey } from './ssh.js';
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
  'keyring',
  'ssh_key',
  'ssh_host',
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
// A line: the subject is the relation of the object ("A is the delegate of B"). The object is a principal
// or a thing; the relation is a role its type declares in the authorization schema.
export const RelationName = z.string().regex(/^[a-z][a-z_]*[a-z]$/).max(64);
export const RelationInput = z.object({ subjectId: Id, relation: RelationName, objectId: Id }).strict();
export const ObjectType = z.enum(['principal', ...ResourceKind.options]);
export const Relation = RelationInput.extend({
  objectType: ObjectType,
  subjectName: Name,
  objectName: Name,
  createdAt: Time,
});
export const ApiError = z.object({
  error: z.object({ code: z.string(), message: z.string(), details: Json.optional() }),
});
export const Ok = z.object({ ok: z.literal(true) });

const FieldChoice = z.object({
  value: z.string().min(1).max(200),
  label: z.string().min(1).max(200),
  values: z.record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/), z.string()).default({}),
}).strict();
const Field = z.object({
  name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/),
  label: z.string(),
  secret: z.boolean().optional(),
  // A file field takes the text of a file the service issued, such as a JSON key.
  inputType: z.enum(['text', 'password', 'file']).optional(),
  required: z.boolean().optional(),
  placeholder: z.string().optional(),
  note: z.string().optional(),
  pattern: z.string().optional(),
  choices: z.array(FieldChoice).min(1).max(100).optional(),
  defaultValue: z.string().max(1000).optional(),
  when: z.object({ field: z.string(), values: z.array(z.string()).min(1) }).strict().optional(),
  visibility: z.enum(['application', 'connection']).optional(),
}).superRefine((field, context) => {
  const choices = field.choices ?? [];
  if (new Set(choices.map(choice => choice.value)).size !== choices.length)
    context.addIssue({ code: 'custom', path: ['choices'], message: 'Use a unique value for each choice.' });
});
const OutputMap = z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.string());
const CredentialOutputMap = z.record(z.string().regex(/^[A-Z_][A-Z0-9_]*$/), z.union([
  z.string(),
  z.array(z.union([z.string().max(8192), z.object({ pointer: z.string().max(1000) }).strict()])).min(1).max(32),
]));
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
export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
export const OAuthDefinition = z.object({
  browserTokenExchange: z.enum(['available', 'unavailable', 'unknown']).optional(),
  application: z.enum(['required', 'implicit']).default('required'),
  grantType: z.enum(['authorization_code', 'client_credentials', DEVICE_CODE_GRANT]).optional(),
  issuer: z.url().optional(),
  registrationUrl: z.url().optional(),
  authorizeUrl: UrlTemplate.optional(),
  deviceAuthorizationUrl: UrlTemplate.optional(),
  tokenUrl: UrlTemplate,
  // Account checks are no longer run. Saved connections keep the method they were created with, so it stays readable.
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
}).refine(value => value.grantType === 'client_credentials' || value.grantType === DEVICE_CODE_GRANT || Boolean(value.authorizeUrl), {
  path: ['authorizeUrl'], message: 'An authorization code flow requires an authorization URL.',
}).refine(value => value.grantType !== DEVICE_CODE_GRANT || Boolean(value.deviceAuthorizationUrl), {
  path: ['deviceAuthorizationUrl'], message: 'A device flow requires a device authorization URL.',
});
export const TokenDefinition = z.object({
  fields: z.array(Field).min(1),
  outputs: CredentialOutputMap,
  resolver: z.literal('vultr-role').optional(),
  bindFields: z.boolean().optional(),
  constants: z.record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/), z.string()).optional(),
  // Outputs a command receives as a file, its environment variable naming the path, unless its input asks otherwise.
  files: z.array(z.string().regex(/^[A-Z_][A-Z0-9_]*$/)).max(32).optional(),
  // The account a pasted JSON document names, shown so the owner can tell which identity it holds.
  account: z.object({ field: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/), pointer: z.string().max(1000) }).strict().optional(),
  // Account checks are no longer run. Saved connections keep the method they were created with, so it stays readable.
  identity: z.object({
    url: UrlTemplate,
    headers: z.record(z.string(), z.string()),
    id: PointerList,
    name: PointerList,
  }).strict().optional(),
  console: z.url().optional(),
  instructions: z.string().optional(),
  hint: z.string().optional(),
}).superRefine((value, context) => {
  if (value.files?.some(name => !Object.hasOwn(value.outputs, name)))
    context.addIssue({ code: 'custom', path: ['files'], message: 'Deliver only declared outputs as files.' });
  if (value.account && !value.fields.some(field => field.name === value.account!.field))
    context.addIssue({ code: 'custom', path: ['account'], message: 'Read the account from a declared field.' });
});
export const AuthKind = z.enum(['oauth', 'token', 'aws', 'ovh', 'approval']);
export type AuthKindName = z.infer<typeof AuthKind>;
export const AwsDefinition = z.object({ hint: z.string().optional() }).strict();
export const OvhDefinition = z.object({
  authorization: z.enum(['api_key', 'consumer_key']),
  apiBaseUrl: UrlTemplate,
  fields: z.array(Field).min(1),
  scopes: Scopes.default({ default: [], separator: '\n' }),
  outputs: OutputMap,
  hint: z.string().optional(),
}).strict();
const methodMetadata = {
  name: Name,
  docs: z.url().optional(),
  console: UrlTemplate.optional(),
  preparation: z.object({
    scopeSelection: z.enum(['optional', 'required', 'hidden']).default('optional'),
    instructions: z.array(z.union([z.string().max(2000), z.object({ ja: z.string().max(2000), en: z.string().max(2000) }).strict()])).max(10).default([]),
    docs: z.boolean().default(false),
  }).strict().optional(),
};
export const OAuthMethod = z
  .object({ ...methodMetadata, kind: z.literal('oauth'), config: OAuthDefinition })
  .strict();
export const TokenMethod = z
  .object({ ...methodMetadata, kind: z.literal('token'), config: TokenDefinition })
  .strict();
export const AwsMethod = z.object({ ...methodMetadata, kind: z.literal('aws'), config: AwsDefinition }).strict();
export const OvhMethod = z.object({ ...methodMetadata, kind: z.literal('ovh'), config: OvhDefinition }).strict();
export const ApprovalMethod = z.object({ ...methodMetadata, kind: z.literal('approval'), config: z.object({
  adapter: z.literal('runpod-flash'), fields: z.array(Field).default([]),
  scopes: Scopes.default({ default: [], separator: ' ' }), outputs: OutputMap,
  hint: z.string().optional(),
}).strict() }).strict();
export const MethodDefinition = z.discriminatedUnion('kind', [OAuthMethod, TokenMethod, AwsMethod, OvhMethod, ApprovalMethod]);
export type MethodDescription = z.infer<typeof MethodDefinition>;
const methodCatalogMetadata = {
  id: z.string().min(1),
  builtin: z.boolean(),
  availability: z.enum(['ready', 'app-required', 'unavailable']),
  defaultName: Name,
  registration: z.object({ kind: z.enum(['input', 'authorization']),
    device: z.enum(['browser', 'cli']), browserExchange: z.enum(['available', 'unavailable', 'unknown']),
    tokenAlternatives: z.array(z.string()) }).strict(),
};
export const CatalogMethod = z.discriminatedUnion('kind', [
  OAuthMethod.extend(methodCatalogMetadata),
  TokenMethod.extend(methodCatalogMetadata),
  AwsMethod.extend(methodCatalogMetadata),
  OvhMethod.extend(methodCatalogMetadata),
  ApprovalMethod.extend(methodCatalogMetadata),
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
    targets: z.array(z.object({
      id: MethodKey,
      name: Name,
      api: z.url().optional(),
      methods: z.array(MethodKey).min(1),
    }).strict()).max(32).optional(),
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
export const validInputName = (name: string) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) &&
  !/^(FOUNDATION_|LD_|DYLD_)|^(NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|GIT_CONFIG_COUNT|GIT_CONFIG_SYSTEM)$/u.test(name);
export const Input = z
  .object({
    name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
    source: Source,
    // Without a format, a connection output its method delivers as a file is a file, and anything else is text.
    format: z.enum(['text', 'file', 'json']).optional(),
    pointer: z.string().optional(),
  })
  .strict();
export type InjectionInput = z.infer<typeof Input>;

const resourceBase = {
  id: Id,
  ownerId: Id,
  name: Name,
  createdAt: Time,
  updatedAt: Time,
  version: z.number().int().positive(),
  permissions: z.array(Action),
};
const custodyMetadata = {
  recipients: z.array(Id).default([]),
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
    fields: z.record(z.string(), z.string()).default({}),
    settings: z.array(z.object({ name: z.string(), label: z.string(), value: z.string() })).default([]),
    methodName: z.string(),
    methodKind: AuthKind,
    services: z.array(z.object({ id: z.string(), name: Name })).default([]),
    account: z.string(),
    accountId: z.string().nullable().default(null),
    accountVerified: z.boolean().default(false),
    scopes: z.array(z.string()),
    scopesStatus: z.enum(['unknown', 'requested', 'reported']).default('unknown'),
    outputs: z.array(z.string()),
    state: z.enum(['ready', 'reconnect', 'disconnecting', 'uncertain']),
    appId: Id.nullable(),
    generation: Id.optional(),
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
// The public keys a principal verified, as one list it signs. Its devices read the list from the signature.
export const KeyringResource = z.object({
  ...resourceBase,
  kind: z.literal('keyring'),
  data: z.object({ revision: z.number().int().positive(), signature: z.string() }),
});
// An SSH public key, and the private key kept as a variable of the same owner when it is kept here at all.
export const SSHKeyData = z.object({
  publicKey: SSHPublicKey, algorithm: z.string(), fingerprint: SSHFingerprint, purpose: z.string().max(500),
  privateKeyId: Id.nullable(), revokedAt: Time.nullable(),
});
export const SSHKeyResource = z.object({ ...resourceBase, kind: z.literal('ssh_key'), data: SSHKeyData });
// A server whose accounts let SSH keys in, known by the host keys it proves itself with.
export const SSHHostData = z.object({
  address: SSHAddress, port: z.number().int().min(1).max(65535), hostKeys: z.array(SSHPublicKey).min(1).max(16),
  authorizedKeysFile: AuthorizedKeysFile,
});
export const SSHHostResource = z.object({ ...resourceBase, kind: z.literal('ssh_host'), data: SSHHostData });
export const Resource = z.discriminatedUnion('kind', [
  VariableResource,
  ConnectionResource,
  ServiceResource,
  MethodResource,
  AppResource,
  ObjectResource,
  KeyringResource,
  SSHKeyResource,
  SSHHostResource,
]);
export type ResourceView = z.infer<typeof Resource>;
export type ConnectionView = z.infer<typeof ConnectionResource>;
export const NewResource = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('service'), name: Name, definition: ServiceInputDefinition }).strict(),
  z.object({ kind: z.literal('method'), name: Name, definition: MethodDefinition }).strict(),
]);
export const UpdateResource = z
  .object({
    version: z.number().int().positive(),
    name: Name.optional(),
    definition: z.union([ServiceInputDefinition, MethodDefinition]).optional(),
  })
  .strict();

export const Invocation = z.object({
  name: z.string().regex(/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/),
  input: JsonObject,
}).strict();
export const Operation = Invocation.extend({
  inputs: z.array(z.object({
    pointer: z.string(),
    label: z.string().min(1).max(100),
    secret: z.boolean().default(false),
    multiline: z.boolean().default(false),
    site: z.url().optional(),
  }).strict()).max(16).default([]),
});
export type RequestedOperation = z.infer<typeof Operation>;
// What an operation does, in the words shown to the one asked to approve it: Japanese and English.
export const OperationTitle = z.object({ ja: z.string(), en: z.string() }).strict();
export type OperationTitle = z.infer<typeof OperationTitle>;
const Named = z.object({ id: Id, name: Name });
// A change its requester has made its own side of, waiting on the side the request is sent to: a line that needs both
// its ends, or something passed to a new owner. The requester makes it once that side agrees.
export const Proposal = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('line'), subject: Named, relation: RelationName, object: Named }),
  z.object({ kind: z.literal('transfer'), item: Named, to: Named }),
]);
export const DeviceRequest = z.object({
  id: Id,
  name: Name,
  publicKey: PublicKey,
  state: z.enum(['pending', 'approving', 'approved']),
  principalId: Id.nullable(),
  createdAt: Time,
  expiresAt: Time,
});
export const Payment = z.object({
  available: z.boolean(),
  required: z.boolean(),
  active: z.boolean(),
  payer: Principal.pick({ id: true, name: true }).nullable(),
});
export const Usage = z.object({
  storageBytes: z.number().nonnegative(),
  storageLimit: z.number().positive(),
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
export const PageQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(100),
  after: z.string().optional(),
});
// The lines onto an object or from a subject, of one relation or onto one type of object if asked.
export const RelationQuery = PageQuery.extend({
  object: Id.optional(),
  subject: Id.optional(),
  relation: RelationName.optional(),
  objectType: ObjectType.optional(),
}).refine((query) => Boolean(query.object) !== Boolean(query.subject), 'Choose the object or the subject of the lines.');
