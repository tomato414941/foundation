#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import { open as openFile, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import packageInfo from '../package.json' with { type: 'json' };
import {
  ApprovalRequest,
  Credential,
  Id,
  JsonObject,
  Input,
  Name,
  RequestInput,
  Resource,
  Sealed,
  listOf,
} from '../../shared/contracts.js';
import type { ResourceView } from '../../shared/contracts.js';
import { Session } from '../../shared/session.js';
import { newEncryptionKey, open as openSealed, unbase64url, unwrap } from '../../shared/encryption.js';
import { bindKeys, fingerprint, newIdentityKeys, PrivateKeys, publicPart, signBinding, SignedBinding } from '../../shared/authority.js';
import { Task } from '../../shared/runtime-protocol.js';
import type { TaskView } from '../../shared/runtime-protocol.js';
import { Client, ApiError } from './client.js';
import { configPath, origin, readIdentity, saveIdentity, secureWrite } from './config.js';
import { execute } from './execute.js';
import { localInputs, privateClient } from './custody.js';
import { startAgent } from './agent.js';
import { executionClient } from './executions.js';
import { ExecutionInput, ExecutionResponse, Invocation, DefinitionDescription, Execution } from '../../shared/executions.js';
import { OperationMaterial } from '../../shared/execution-client.js';
import { managedAgent } from './managed-agent.js';
import { startMcp } from './mcp.js';
import { FunctionClient } from '../../shared/function-client.js';
import { FunctionDefinition } from '../../shared/contracts.js';
import { connectionClient, flowOutput, saveApp, startConnection } from './connections.js';
import type { FlowProgress } from '../../shared/connection-client.js';

const help = `Foundation ${packageInfo.version}

Usage: foundation <command> [options]

  login [--origin URL]                  Sign in by approving this machine in a browser
  login --key TOKEN [--origin URL]      Sign in with a key issued in a browser
  init --name NAME [--origin URL]       Register this machine as a new principal
  status                               Show this machine and its accessible principals
  request-access [--to ID] [--wait]     Ask a person to make this machine their agent
  api METHOD /api/PATH [--body JSON]    Call the common Foundation API
  definition list                      List processing definitions and their inputs
  execution start --body JSON          Prepare operations and return their continuation URL
  execution history                   List executions visible to this principal
  execution respond ID --body JSON     Supply public inputs and consent
  execution cancel ID                  Cancel a prepared operation
  execution run NAME --body JSON       Execute an operation (private material via --fields)
  execution continue ID [--fields JSON] Resume an operation awaiting private input
  execution share-result ID            Share a legacy result using its existing permissions
  schema [--output FILE]                Read the OpenAPI specification
  mcp                                  Serve local MCP using this identity's signing keys
  trust ID --fingerprint VALUE         Trust identity keys verified with their holder
  agent start [--id ID]                Register this machine as an execution environment
  app NAME --method ID --client-id ID  Encrypt an application (--for ENV to allow use)
  connect --method ID                  Encrypt and save a connection on this device
  connect wait ID                      Continue after service authorization
  keep NAME (--file FILE | --stdin)    Encrypt and save a variable (--for ENV to allow execution)
  read ID [--output FILE]               Decrypt a variable you can reveal
  exec --inputs JSON -- COMMAND ...    Deliver inputs to a local command
  run --environment ID --request JSON  Run an HTTP request on the selected executor
  function list                       List accessible functions and their inputs
  function show ID                    Read a function's interface or permitted definition
  function create --body JSON         Approve and save a function definition
  function update ID --body JSON      Approve and replace a function definition
  function settings ID                Read function execution settings
  function configure ID --environment ID Approve the execution environment and input access
  function unconfigure ID             Clear execution settings and revoke input access
  function invoke ID [--arguments JSON] Invoke a function (--id ID for retries, --wait for result)
  function result ID                  Read an execution (--wait to wait for completion)
  function cancel ID                  Cancel a function execution
  function delete ID                  Delete a function
  run --environment ID -- COMMAND ...  Run a command in an environment
  wait ID [--timeout SECONDS]           Wait for a run to finish
  retry ID                             Continue an execution using its saved consent
  request --body JSON                  Create an approval request
  request wait ID [--timeout SECONDS]  Wait for an approval request
  export --output FILE                 Download an encrypted account export

Options:
  --owner ID             Choose the principal that owns a new item or run
  --key TOKEN            A key issued in a browser (@FILE or @- to read it)
  --name NAME            How this machine appears when it signs in (default: host name)
  --origin URL           Choose a server when signing in or registering
  --for ID               Allow this executor to use the content (repeatable)
  --app ID               Application to use for a connection
  --fields JSON          Connection or application fields (@FILE or @- accepted)
  --aws JSON             AWS authentication, region, and optional role (@FILE or @- recommended)
  --client-secret VALUE  Application secret (@FILE or @- recommended)
  --isolation MODE       process for trusted local code, or container
  --image IMAGE          Command container image pinned with @sha256:DIGEST
  --inputs JSON         Inputs for exec or a remote command (default: [])
  --wait                 Wait after starting a run or requesting approval
  --timeout SECONDS      Maximum waiting or command time (default: 60 for commands)
  --output FILE          Write the result to a private file
  --force                Replace an existing output file
  --upload FILE          Send a binary body with the api command
  --help                 Show this help
  --version              Show the version

JSON and the key may be supplied as @FILE, or @- to read standard input.
Signing in makes this machine act as you, with your encryption key. Registering
with --name creates a separate principal instead.
The unlock portion of a sign-in key stays on this machine. Verify fingerprints
with each identity holder before trusting their keys. --for permits that executor
to read the content and use it in commands or HTTP requests you supply.
Without --for, content is readable only by its approved readers. Updates preserve
existing permissions unless --for is supplied. Local exec decrypts on this machine.
exec masks input values in stdout and stderr. read deliberately reveals content.
Ctrl+C while waiting stops the wait; use the API to cancel the remote operation.

Identity: $XDG_CONFIG_HOME/foundation/identity.json (defaults to ~/.config)
Environment identity: FOUNDATION_ORIGIN, FOUNDATION_TOKEN,
FOUNDATION_PRINCIPAL_ID, FOUNDATION_PRIVATE_KEYS, FOUNDATION_KEY_BINDING.
The last two values are base64url-encoded JSON; omit both for metadata-only access.
`;
const textOption = { type: 'string' as const },
  booleanOption = { type: 'boolean' as const };
const options = {
  name: textOption,
  key: textOption,
  origin: textOption,
  owner: textOption,
  to: textOption,
  message: textOption,
  body: textOption,
  file: textOption,
  stdin: booleanOption,
  for: { type: 'string' as const, multiple: true as const },
  fingerprint: textOption,
  id: textOption,
  isolation: textOption,
  image: textOption,
  managed: booleanOption,
  once: booleanOption,
  method: textOption,
  'client-id': textOption,
  'client-secret': textOption,
  app: textOption,
  connection: textOption,
  fields: textOption,
  scopes: textOption,
  aws: textOption,
  parameters: textOption,
  'redirect-uri': textOption,
  inputs: textOption,
  request: textOption,
  save: textOption,
  arguments: textOption,
  environment: textOption,
  timeout: textOption,
  wait: booleanOption,
  output: textOption,
  force: booleanOption,
  upload: textOption,
  help: booleanOption,
  version: booleanOption,
};
type Arguments = ReturnType<typeof argumentsFor>;
function argumentsFor(args: string[]) {
  return parseArgs({ args, options, allowPositionals: true, allowNegative: true, strict: true });
}
function print(value: unknown) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}
function requireArgument(value: string | undefined, message: string): string {
  if (!value) throw new Error(message);
  return value;
}
async function stdin(max = 2_200_000) {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const value = Buffer.from(chunk);
    size += value.length;
    if (size > max) throw new Error('The input is too large.');
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}
async function text(value: string) {
  return value === '@-'
    ? (await stdin()).toString('utf8')
    : value.startsWith('@')
      ? await readFile(value.slice(1), 'utf8')
      : value;
}
async function json(value: string | undefined, fallback: unknown = {}) {
  if (!value) return fallback;
  const source = await text(value);
  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new Error('Invalid JSON. Supply JSON text, @FILE, or @-.');
  }
}
function seconds(value: string | undefined, fallback: number, max = 86400) {
  if (value === undefined) return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > max)
    throw new Error('Choose a time limit between 1 and ' + max + ' seconds.');
  return number;
}
// A link that also carries this identity's public key fingerprint after '#', which browsers never send to the server,
// so whoever opens it can verify this identity's public key without typing anything.
async function linked(url: string, identity: Client['identity']) {
  return identity.binding ? url + (url.includes('#') ? '&' : '#') + 'fingerprint=' + await fingerprint(identity.binding) : url;
}
async function output(value: unknown, args: Arguments) {
  const body = JSON.stringify(value, null, 2) + '\n';
  if (args.values.output) await secureWrite(args.values.output, body, !!args.values.force);
  else process.stdout.write(body);
}
async function download(response: Response, path: string, replace: boolean) {
  if (!response.body) throw new Error('Foundation returned an empty response.');
  const destination = resolve(path),
    temporary = replace ? join(dirname(destination), '.foundation-' + randomUUID()) : destination;
  const file = await openFile(temporary, 'wx', 0o600);
  let done = false;
  try {
    await pipeline(
      Readable.fromWeb(response.body as import('node:stream/web').ReadableStream<Uint8Array>),
      file.createWriteStream(),
    );
    if (replace) await rename(temporary, destination);
    done = true;
  } finally {
    await file.close().catch(() => {});
    if (!done) await rm(temporary, { force: true });
  }
}
async function signInWithKey(base: string, imported: string) {
  const parts = imported.trim().split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]!) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1]!))
    throw new Error('Use a sign-in key containing an authentication token and a separate encryption unlock code.');
  const [token, unlock] = parts as [string, string];
  let response: Response;
  try {
    response = await fetch(base + '/api/session', {
      headers: { authorization: 'Bearer ' + token },
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new Error('Could not reach Foundation. Check --origin and your network connection.');
  }
  if (!response.ok) throw new Error('Sign-in failed (HTTP ' + response.status + ').');
  const current = Session.parse(await response.json());
  if (!current.principal) throw new Error('The key was not accepted.');
  if (!current.wrappedKey)
    throw new Error('This key does not carry an encryption key. Issue it from a browser that can open encrypted values.');
  const keys = PrivateKeys.parse(await unwrap(current.wrappedKey, unbase64url(unlock), current.principal.id).catch(() => {
    throw new Error('The encryption key could not be unlocked with this key.');
  }));
  const unsigned = new Client({ origin: base, principalId: current.principal.id, token, keys: null, binding: null });
  const { binding } = await unsigned.json('/api/identities/' + current.principal.id + '/binding', {}, SignedBinding);
  await signBinding(binding, keys);
  const identity = { origin: base, principalId: current.principal.id, token, keys, binding };
  await saveIdentity(identity);
  // This device can now open its items, so it seals again any that the server lists as needing it.
  const { done, failed } = await privateClient(new Client(identity)).custody.reprotectPending().catch((error: unknown) => {
    process.stderr.write('Could not check for items to seal again: ' +
      (error instanceof Error ? error.message : String(error)) + '\n');
    return { done: [], failed: [] };
  });
  if (done.length) process.stderr.write('Sealed ' + done.length + ' item(s) again for their current readers and grants.\n');
  if (failed.length) process.stderr.write(failed.length + ' item(s) could not be sealed again yet; signing in again retries them.\n');
  print({ principal: { id: current.principal.id, name: current.principal.name }, origin: base, identity: configPath(),
    fingerprint: await fingerprint(binding) });
}
async function login(args: Arguments) {
  const base = origin(args.values.origin);
  if (args.values.key) return signInWithKey(base, await text(args.values.key));
  const name = Name.parse(args.values.name || hostname()),
    device = await newEncryptionKey();
  let response: Response;
  try {
    response = await fetch(base + '/api/auth/devices', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, publicKey: device.publicKey }),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new Error('Could not reach Foundation. Check --origin and your network connection.');
  }
  if (!response.ok) throw new Error('Sign-in could not start (HTTP ' + response.status + ').');
  const started = z
    .object({ id: Id, code: z.string(), poll: z.string(), url: z.url(), expiresAt: z.string() })
    .parse(await response.json());
  process.stderr.write(`Open ${started.url}\nand enter the code ${started.code.slice(0, 4)}-${started.code.slice(4)} to sign in as yourself.\n`);
  const deadline = new Date(started.expiresAt).getTime();
  while (true) {
    if (Date.now() >= deadline) throw new Error('The sign-in was not approved in time. Run foundation login again.');
    await delay(2000);
    const polled = await fetch(`${base}/api/auth/devices/${started.id}?poll=${encodeURIComponent(started.poll)}`, {
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    }).catch(() => null);
    if (!polled) continue;
    if (polled.status === 404) throw new Error('The sign-in was not approved in time. Run foundation login again.');
    if (polled.status >= 500) continue;
    if (!polled.ok) throw new Error('Sign-in failed (HTTP ' + polled.status + ').');
    const result = z
      .object({ state: z.string(), sealed: Sealed.nullable() })
      .parse(await polled.json());
    if (result.state !== 'approved' || !result.sealed) continue;
    const imported = new TextDecoder().decode(
      await openSealed(result.sealed, device.privateKey, started.id, 'device:' + started.id),
    );
    return signInWithKey(base, imported);
  }
}
async function initialize(args: Arguments) {
  const path = configPath();
  const base = origin(args.values.origin);
  if (args.values.key) throw new Error('Use foundation login --key to sign in with a key.');
  const name = Name.parse(args.values.name || hostname()),
    keys = await newIdentityKeys();
  let response: Response;
  try {
    response = await fetch(base + '/api/auth/enroll', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, publicKey: publicPart(keys.encryption) }),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new Error('Could not reach Foundation. Check --origin and your network connection.');
  }
  if (!response.ok) throw new Error('Registration failed (HTTP ' + response.status + ').');
  const registered = z
    .object({ principal: z.object({ id: Id, name: Name }), credential: Credential, token: z.string() })
    .parse(await response.json());
  const binding = bindKeys(registered.principal.id, keys), identity = {
    origin: base,
    principalId: registered.principal.id,
    token: registered.token,
    keys, binding,
  };
  await saveIdentity(identity);
  await new Client(identity).json('/api/principals/' + registered.principal.id + '/binding', {
    method: 'PUT', body: await signBinding(binding, keys),
  }, SignedBinding);
  print({ principal: registered.principal, origin: base, identity: path, fingerprint: await fingerprint(binding) });
}
async function waitFor<T>(fetcher: () => Promise<T>, state: (value: T) => string, timeout: number) {
  const deadline = Date.now() + timeout * 1000;
  while (true) {
    const value = await fetcher();
    if (!['pending', 'running', 'queued'].includes(state(value))) return value;
    if (Date.now() >= deadline)
      throw new Error('The operation is still pending. Run the wait command again to continue.');
    await delay(1500);
  }
}
async function keep(client: Client, args: Arguments, owner: string) {
  const name = Name.parse(requireArgument(args.positionals[0], 'Supply the variable name.'));
  if (Boolean(args.values.file) === Boolean(args.values.stdin))
    throw new Error('Choose exactly one of --file or --stdin.');
  const content = args.values.file ? await readFile(args.values.file) : await stdin(1_000_000);
  if (content.length > 1_000_000) throw new Error('A variable must be at most 1,000,000 bytes.');
  let after: string | null = null,
    existing: Extract<ResourceView, { kind: 'variable' }> | undefined;
  do {
    const search = new URLSearchParams({
      kind: 'variable',
      query: name,
      limit: '200',
      ...(after ? { after } : {}),
    });
    const page = await client.json('/api/principals/' + owner + '/resources?' + search, {}, listOf(Resource));
    existing = page.items.find(
      (item): item is Extract<ResourceView, { kind: 'variable' }> =>
        item.kind === 'variable' && item.name === name,
    );
    after = page.next;
  } while (after && !existing);
  const operations = executionClient(client), previous = existing ? await operations.custody.read(existing.id) : undefined;
  const completed = await operations.execute({ name: 'variable.save', input: { ownerId: owner, name,
    ...(existing ? { resourceId: existing.id, version: previous!.version } : {}),
    ...(args.values.for ? { environmentIds: args.values.for.map(id => Id.parse(id)) } : {}) } }, { value: content });
  if (!('kind' in completed) || completed.kind !== 'saved') throw new Error('Finish saving the variable.');
  const result = completed.resource;
  await output(result, args);
}

async function taskOutput(client: Client, task: TaskView, args: Arguments) {
  const result = await privateClient(client).custody.result(task);
  const execution = await client.json('/api/executions/' + (task.intent.operationContext?.id ?? task.id), {}, Execution);
  if (result?.ok) execution.results[task.intent.operationContext?.index ?? 0] = result.result;
  await output(execution, args);
}
async function main(argv: string[]) {
  const boundary = argv.indexOf('--'),
    commandArguments = boundary < 0 ? [] : argv.slice(boundary + 1),
    head = boundary < 0 ? argv : argv.slice(0, boundary);
  if (head.length === 0 || head.includes('--help')) {
    process.stdout.write(help);
    return 0;
  }
  if (head.includes('--version')) {
    process.stdout.write(packageInfo.version + '\n');
    return 0;
  }
  const command = head[0]!,
    args = argumentsFor(head.slice(1));
  if (command === 'init') {
    await initialize(args);
    return 0;
  }
  if (command === 'login') {
    await login(args);
    return 0;
  }
  if (command === 'agent' && args.positionals[0] === 'managed') return managedAgent();
  const client = new Client(await readIdentity(args.values.origin));
  const current = await client.session();
  if (!current.principal) throw new Error('The machine identity is no longer valid.');
  const owner = Id.parse(args.values.owner ?? current.principal.id);
  if (command === 'mcp') return startMcp(client);
  if (command === 'status') {
    const { wrappedKey: _wrappedKey, ...status } = current;
    await output({ ...status, ...(client.identity.binding ? { fingerprint: await fingerprint(client.identity.binding),
      verificationUrl: await linked(new URL('/account/trust?principal=' + current.principal.id, client.identity.origin).href, client.identity) } : {}) }, args);
    return 0;
  }
  if (command === 'trust') {
    const { custody } = privateClient(client), id = Id.parse(requireArgument(args.positionals[0], 'Supply an identity ID.'));
    if (!args.values.fingerprint) {
      const identity = await custody.inspectIdentity(id);
      await output({ identityId: id, fingerprint: identity.fingerprint,
        next: 'Verify this fingerprint with the identity holder, then repeat with --fingerprint.' }, args);
    } else {
      const identity = await custody.trustIdentity(id, args.values.fingerprint);
      await output({ identityId: id, fingerprint: identity.fingerprint, trusted: true }, args);
    }
    return 0;
  }
  if (command === 'agent') {
    if (args.positionals[0] !== 'start') throw new Error('Use foundation agent start.');
    return startAgent(client, { id: args.values.id ? Id.parse(args.values.id) : undefined,
      ownerId: owner, name: Name.parse(args.values.name ?? hostname()),
      isolation: z.enum(['process', 'container']).parse(args.values.isolation ?? 'process'),
      image: args.values.image, managed: args.values.managed, once: args.values.once });
  }
  if (command === 'app') {
    const resource = await saveApp(client, { ownerId: owner,
      name: requireArgument(args.positionals[0], 'Supply an application name.'), id: args.values.id,
      methodId: requireArgument(args.values.method, 'Choose --method ID.'), clientId: args.values['client-id'] ?? '',
      clientSecret: args.values['client-secret'] === undefined ? undefined : await text(args.values['client-secret']),
      fields: await json(args.values.fields, {}), environments: args.values.for });
    await output(resource, args); return 0;
  }
  if (command === 'definition') {
    if ((args.positionals[0] ?? 'list') !== 'list') throw new Error('Use foundation definition list.');
    await output(await client.json('/api/definitions', {}, listOf(DefinitionDescription)), args); return 0;
  }
  if (command === 'execution') {
    const action = args.positionals[0] ?? 'list';
    if (action === 'list') await output(await client.json('/api/definitions', {}, listOf(DefinitionDescription)), args);
    else if (action === 'history') await output(await client.json('/api/executions', {}, listOf(Execution)), args);
    else if (action === 'get') await output(await client.json('/api/executions/' + Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.')), {}, Execution), args);
    else if (action === 'start') await output(await client.json('/api/executions', { method: 'POST', body: ExecutionInput.parse(await json(args.values.body, {})) }, Execution), args);
    else if (action === 'respond') await output(await client.json('/api/executions/' + Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.')) + '/respond', { method: 'POST', body: ExecutionResponse.parse(await json(args.values.body, {})) }, Execution), args);
    else if (action === 'cancel') await output(await client.json('/api/executions/' + Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.')) + '/cancel', { method: 'POST', body: {} }, Execution), args);
    else if (action === 'share-result') {
      const execution = await client.json('/api/executions/' + Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.')), {}, Execution);
      const custody = privateClient(client).custody;
      const shared = [];
      for (const step of execution.steps) {
        const reference = step.runs.at(-1);
        if (reference?.kind !== 'run') continue;
        const task = await client.json('/api/runtime/runs/' + reference.id, {}, Task);
        const result = await custody.shareLegacyResult(task);
        shared.push({ id: task.id, readers: result.receipt && 'content' in result.receipt
          ? result.receipt.content.policy.readers.map(reader => reader.principalId) : [] });
      }
      await output({ id: execution.id, results: shared }, args);
    }
    else if (action === 'run' || action === 'continue') {
      const material = OperationMaterial.parse(await json(args.values.fields, {}));
      const invocation = action === 'run' ? Invocation.parse({ name: requireArgument(args.positionals[1], 'Supply an operation name.'), input: await json(args.values.body, {}) }) : null;
      if (invocation) {
        const catalog = await client.json('/api/definitions', {}, listOf(DefinitionDescription));
        const definition = catalog.items.find(item => item.name === invocation.name);
        if (!definition) throw new Error('Choose an available operation.');
        if (definition.execution === 'server') {
          await output(await client.json('/api/definitions/' + invocation.name + '/executions', { method: 'POST', body: invocation.input }), args);
          return 0;
        }
      }
      const operations = executionClient(client);
      const result = action === 'continue' ? await operations.continue(Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.')), material)
        : await operations.execute(invocation!, material);
      await output('flow' in result ? flowOutput(result) : result, args);
    } else throw new Error('Choose execution list, start, respond, run, get, continue, share-result, or cancel.');
    return 0;
  }
  if (command === 'connect') {
    if (args.values.environment || args.values.for) throw new Error('Register on this device. Select an execution environment when running a program.');
    const flowClient = connectionClient(client), action = args.positionals[0] ?? 'start';
    let progress: FlowProgress | Awaited<ReturnType<typeof startConnection>>;
    if (action === 'start') progress = await startConnection(client, { ownerId: owner,
      methodId: requireArgument(args.values.method, 'Choose --method ID.'), name: args.values.name,
      appId: args.values.app, connectionId: args.values.connection,
      fields: await json(args.values.fields, {}), scopes: args.values.scopes === undefined ? undefined : await json(args.values.scopes, []),
      aws: args.values.aws ? await json(args.values.aws) : undefined,
      redirectUri: args.values['redirect-uri'] });
    else {
      const executionId = Id.parse(requireArgument(args.positionals[1], 'Supply an execution ID.'));
      const execution = await client.json('/api/executions/' + executionId, {}, Execution);
      if (!execution.waiting?.continuation) { await output(execution, args); return execution.state === 'succeeded' ? 0 : 1; }
      const id = execution.waiting.continuation.id;
      if (action === 'cancel') progress = await flowClient.cancel(id);
      else if (action === 'complete') {
        const value = await text(requireArgument(args.values.parameters, 'Supply the authorization response with --parameters.'));
        progress = await flowClient.complete(id, value.includes('://') ? new URL(value).search.slice(1) : value.replace(/^\?/, ''));
      } else if (action === 'status' || action === 'wait') progress = await flowClient.progress(id);
      else throw new Error('Choose connect start, status, wait, complete, or cancel.');
    }
    if (args.values.wait || action === 'wait') {
      const deadline = Date.now() + seconds(args.values.timeout, 600) * 1000;
      while (progress.kind === 'pending' || (action === 'wait' && progress.kind === 'authorize')) {
        if (Date.now() >= deadline) break;
        await delay(1000);
        progress = await flowClient.progress(progress.flow.id);
      }
    }
    await output(flowOutput(progress), args);
    return ['failed', 'cancelled'].includes(progress.kind) ? 1 : 0;
  }
  if (command === 'retry') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply a saved execution ID.'));
    const execution = await client.json('/api/executions/' + id, {}, Execution);
    if (execution.state === 'failed')
      await client.json('/api/executions/' + id + '/resume', { method: 'POST', body: {} }, Execution);
    const result = await executionClient(client).continue(id);
    if ('kind' in result && result.kind === 'run') await taskOutput(client, result.task, args);
    else await output(result, args);
    return 0;
  }
  if (command === 'api' || command === 'schema') {
    const method =
      command === 'schema'
        ? 'GET'
        : requireArgument(args.positionals[0], 'Supply an HTTP method.').toUpperCase();
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method))
      throw new Error('Choose GET, HEAD, POST, PUT, PATCH, or DELETE.');
    const path =
      command === 'schema'
        ? '/api/openapi.json'
        : requireArgument(args.positionals[1], 'Supply an API path beginning with /api/.');
    if (args.values.body && args.values.upload) throw new Error('Choose --body or --upload.');
    const response = await client.response(path, {
      method,
      ...(args.values.body ? { body: await json(args.values.body) } : {}),
      ...(args.values.upload ? { raw: await readFile(args.values.upload) } : {}),
    });
    if (args.values.output) await download(response, args.values.output, !!args.values.force);
    else if (method === 'HEAD' || response.status === 204) print({ status: response.status });
    else if (response.headers.get('content-type')?.includes('json')) print(await response.json());
    else {
      if (!response.body) throw new Error('Foundation returned an empty response.');
      await pipeline(
        Readable.fromWeb(response.body as import('node:stream/web').ReadableStream<Uint8Array>),
        process.stdout,
      );
    }
    return 0;
  }
  if (command === 'keep') {
    await keep(client, args, owner);
    return 0;
  }
  if (command === 'read') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply the resource ID.'));
    const bytes = await privateClient(client).custody.reveal(id);
    if (args.values.output) await secureWrite(args.values.output, bytes, !!args.values.force);
    else process.stdout.write(bytes);
    return 0;
  }
  if (command === 'exec') {
    const inputs = z
      .array(Input)
      .max(32)
      .parse(await json(args.values.inputs, []));
    return execute(await localInputs(client, inputs), commandArguments);
  }
  if (command === 'function') {
    const action = requireArgument(args.positionals[0], 'Choose list, show, create, update, settings, configure, unconfigure, invoke, result, cancel, or delete.');
    const functions = new FunctionClient(client);
    if (action === 'list') { await output(await client.json('/api/functions?limit=100'), args); return 0; }
    if (action === 'create' || action === 'update') {
      const body = z.object({ name: Name, definition: FunctionDefinition, version: z.number().int().positive().optional() }).strict().parse(await json(args.values.body));
      const id = action === 'update' ? Id.parse(requireArgument(args.positionals[1], 'Supply a function ID.')) : undefined;
      const previous = id ? await functions.get(id) : null;
      await output(await new FunctionClient(client, privateClient(client).custody).save({ ownerId: previous?.ownerId ?? owner,
        name: body.name, definition: body.definition, ...(id ? { resourceId: id, version: body.version ?? previous!.version } : {}) }), args);
      return 0;
    }
    const id = Id.parse(requireArgument(args.positionals[1], 'Supply a function or execution ID.'));
    if (action === 'show') { await output(await functions.get(id), args); return 0; }
    if (action === 'settings') { await output(await functions.settings(id), args); return 0; }
    if (action === 'configure' || action === 'unconfigure') {
      const environmentId = action === 'configure' ? Id.parse(requireArgument(args.values.environment, 'Choose an execution environment with --environment ID.')) : null;
      const inputAccess = z.object({ expiresAt: z.iso.datetime().nullable().default(null) }).strict().parse(await json(args.values.body, {}));
      await output(await new FunctionClient(client, privateClient(client).custody).configure(id, { environmentId, inputAccess }), args);
      return 0;
    }
    if (action === 'delete') { await functions.remove(id); return 0; }
    if (action === 'cancel') { await output(await functions.cancel(id), args); return 0; }
    if (action === 'invoke' || action === 'result') {
      const save = z.record(z.string(), Name).parse(await json(args.values.save, {}));
      const invoker = Object.keys(save).length ? new FunctionClient(client, privateClient(client).custody) : functions;
      let result = action === 'invoke' ? await invoker.invoke(id, JsonObject.parse(await json(args.values.arguments, {})),
        { ownerId: owner, save, ...(args.values.id ? { id: Id.parse(args.values.id) } : {}) })
        : await functions.result(id);
      if (args.values.wait) result = await waitFor(() => functions.result(result.id),
        value => value.state, seconds(args.values.timeout, 3600));
      await output(result, args);
      return ['failed', 'cancelled', 'uncertain'].includes(result.state) ? 1 : 0;
    }
    throw new Error('Choose list, show, create, update, settings, configure, unconfigure, invoke, result, cancel, or delete.');
  }
  if (command === 'run') {
    const modes = [args.values.request, commandArguments.length ? true : false].filter(Boolean);
    if (modes.length !== 1) throw new Error('Choose --request or a command after --.');
    const environmentId = Id.parse(requireArgument(args.values.environment, 'Choose an explicit execution environment with --environment ID.'));
    const input = args.values.request
      ? { kind: 'http', request: await json(args.values.request) }
      : {
            kind: 'command',
            command: commandArguments,
            timeoutSeconds: seconds(args.values.timeout, 60, 3600),
            inputs: await json(args.values.inputs, []),
          };
    const started = await executionClient(client).execute({ name: 'run.execute', input: { ownerId: owner, environmentId,
      operation: JsonObject.parse(input),
      save: z.record(z.string(), Name).parse(await json(args.values.save, {})) } });
    if (!('kind' in started) || started.kind !== 'run') throw new Error('Continue the pending run.');
    const run = started.task;
    const result = args.values.wait
      ? await waitFor(
          () => client.json('/api/runtime/runs/' + run.id, {}, Task),
          (value) => value.state,
          seconds(args.values.timeout, 3600),
        )
      : run;
    await taskOutput(client, result, args);
    return ['failed', 'cancelled', 'uncertain'].includes(result.state) ? 1 : 0;
  }
  if (command === 'wait') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply a run ID.'));
    const result = await waitFor(
      () => client.json('/api/executions/' + id, {}, Execution),
      (value) => value.state,
      seconds(args.values.timeout, 3600),
    );
    for (const step of result.steps) {
      const run = step.runs.filter(run => run.kind === 'run').at(-1);
      if (!run) continue;
      const task = await client.json('/api/runtime/runs/' + run.id, {}, Task);
      if (task.receipt) result.results[step.index] = (await privateClient(client).custody.result(task))?.result ?? null;
    }
    await output(result, args);
    return result.state === 'succeeded' ? 0 : 1;
  }
  if (command === 'request-access' || command === 'request') {
    if (command === 'request' && args.positionals[0] === 'wait') {
      const id = Id.parse(requireArgument(args.positionals[1], 'Supply a request ID.'));
      const result = await waitFor(
        () => client.json('/api/requests/' + id, {}, ApprovalRequest),
        (value) => value.state,
        seconds(args.values.timeout, 1800),
      );
      await output(result, args);
      return result.state === 'accepted' ? 0 : 1;
    }
    const input =
      command === 'request-access'
        ? {
            to: args.values.to,
            message: args.values.message ?? hostname(),
            operations: [
              {
                name: 'relation.draw',
                input: { subjectId: current.principal.id, relation: 'agent', objectId: '$approver' },
              },
            ],
          }
        : await json(requireArgument(args.values.body, 'Supply the request as --body JSON.'));
    const request = await client.json(
      '/api/requests',
      { method: 'POST', body: RequestInput.parse(input) },
      ApprovalRequest,
    );
    await output({ ...request, url: await linked(request.url, client.identity) }, args);
    if (args.values.wait) {
      const result = await waitFor(
        () => client.json('/api/requests/' + request.id, {}, ApprovalRequest),
        (value) => value.state,
        seconds(args.values.timeout, 1800),
      );
      await output(result, { ...args, values: { ...args.values, force: true } });
      return result.state === 'accepted' ? 0 : 1;
    }
    return 0;
  }
  if (command === 'export') {
    const path = requireArgument(args.values.output, 'Choose an export file with --output FILE.');
    await download(await client.response('/api/principals/' + owner + '/export'), path, !!args.values.force);
    print({ path: resolve(path) });
    return 0;
  }
  throw new Error('Unknown command: ' + command + '. Run foundation --help.');
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  const message =
    error instanceof ApiError
      ? error.code + ': ' + error.message
      : error instanceof z.ZodError
        ? 'Check the command inputs against foundation schema.'
        : error instanceof Error
          ? error.message
          : 'The command failed.';
  process.stderr.write('foundation: ' + message + '\n');
  process.exitCode = 1;
}
