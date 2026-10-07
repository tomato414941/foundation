#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import { lstat, open as openFile, readFile, rename, rm } from 'node:fs/promises';
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
  Input,
  Name,
  RequestInput,
  Resource,
  listOf,
} from '../../shared/contracts.js';
import type { ResourceView } from '../../shared/contracts.js';
import { Session } from '../../shared/session.js';
import { unbase64url, unwrap } from '../../shared/encryption.js';
import { bindKeys, hash, newIdentityKeys, PrivateKeys, publicPart, signBinding, SignedBinding } from '../../shared/authority.js';
import { RuntimeOperation, Task } from '../../shared/execution.js';
import type { TaskView } from '../../shared/execution.js';
import { Client, ApiError } from './client.js';
import { configPath, origin, readIdentity, saveIdentity, secureWrite } from './config.js';
import { execute } from './execute.js';
import { localInputs, privateClient } from './custody.js';
import { startAgent } from './agent.js';
import { managedAgent } from './managed-agent.js';
import { startMcp } from './mcp.js';
import { connectionClient, flowOutput, saveApp, startConnection } from './connections.js';
import type { FlowProgress } from '../../shared/connection-client.js';

const help = `Foundation ${packageInfo.version}

Usage: foundation <command> [options]

  init --key TOKEN [--origin URL]       Sign in with a key you issued and save it
  init --name NAME [--origin URL]       Register this machine as a new principal
  status                               Show this machine and its accessible principals
  join [--to ID] [--wait]               Ask a person to take on this machine
  api METHOD /api/PATH [--body JSON]    Call the common Foundation API
  schema [--output FILE]                Read the OpenAPI specification
  mcp                                  Serve local MCP using this identity's signing keys
  trust ID --fingerprint VALUE         Trust identity keys verified with their holder
  agent start [--id ID]                Register this machine as an execution environment
  app NAME --method ID --client-id ID  Encrypt an OAuth application (--for ENV to allow use)
  connect --method ID --environment ID Start a connection on the selected executor
  connect wait ID                      Continue after service authorization
  connect accept ID                    Save the reviewed connection and its permissions
  keep NAME (--file FILE | --stdin)    Encrypt and save a secret (--for ENV to allow execution)
  read ID [--output FILE]               Decrypt a secret you can reveal
  exec --inputs JSON -- COMMAND ...    Deliver inputs to a local command
  run --environment ID --request JSON  Run an HTTP request on the selected executor
  run --environment ID --function ID   Run a saved function on the selected executor
  run --environment ID -- COMMAND ...  Run a command in an environment
  wait ID [--timeout SECONDS]           Wait for a run to finish
  retry ID                             Submit the same saved, signed execution request
  request --body JSON                  Create an approval request
  request wait ID [--timeout SECONDS]  Wait for an approval request
  export --output FILE                 Download an encrypted account export

Options:
  --owner ID             Choose the principal that owns a new item or run
  --key TOKEN            A key issued from a browser (@FILE or @- to read it)
  --origin URL           Choose a server when initializing a machine
  --for ID               Allow this executor to use the content (repeatable)
  --caller ID            Accept requests from this identity (repeatable, agent start)
  --app ID               OAuth application to use for a connection
  --fields JSON          Connection or application fields (@FILE or @- accepted)
  --client-secret VALUE  OAuth application secret (@FILE or @- recommended)
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
A key issued in a browser carries your encryption key, so the machine acts as
you. Registering with --name creates a separate principal instead.
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
  caller: { type: 'string' as const, multiple: true as const },
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
  role: textOption,
  parameters: textOption,
  'redirect-uri': textOption,
  inputs: textOption,
  request: textOption,
  save: textOption,
  function: textOption,
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
async function initialize(args: Arguments) {
  const path = configPath();
  try {
    await lstat(path);
    throw new Error(
      'This machine is already initialized. Run foundation status, or use a separate XDG_CONFIG_HOME.',
    );
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
  }
  const base = origin(args.values.origin);
  if (args.values.key) {
    if (args.values.name) throw new Error('Choose --key or --name.');
    const imported = (await text(args.values.key)).trim().split('.');
    if (imported.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(imported[0]!) || !/^[A-Za-z0-9_-]{43}$/.test(imported[1]!))
      throw new Error('Use a sign-in key containing an authentication token and a separate encryption unlock code.');
    const [token, unlock] = imported as [string, string];
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
      throw new Error('This key does not carry an encryption key. Issue it from a browser that can open secrets.');
    const keys = PrivateKeys.parse(await unwrap(current.wrappedKey, unbase64url(unlock), current.principal.id).catch(() => {
      throw new Error('The encryption key could not be unlocked with this key.');
    }));
    const unsigned = new Client({ origin: base, principalId: current.principal.id, token, keys: null, binding: null });
    const { binding } = await unsigned.json('/api/identities/' + current.principal.id + '/binding', {}, SignedBinding);
    await signBinding(binding, keys);
    await saveIdentity({ origin: base, principalId: current.principal.id, token, keys, binding });
    print({ principal: { id: current.principal.id, name: current.principal.name }, origin: base, identity: path,
      fingerprint: await hash(binding) });
    return;
  }
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
  print({ principal: registered.principal, origin: base, identity: path, fingerprint: await hash(binding) });
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
  const name = Name.parse(requireArgument(args.positionals[0], 'Supply the secret name.'));
  if (Boolean(args.values.file) === Boolean(args.values.stdin))
    throw new Error('Choose exactly one of --file or --stdin.');
  const content = args.values.file ? await readFile(args.values.file) : await stdin(1_000_000);
  if (content.length > 1_000_000) throw new Error('A secret must be at most 1,000,000 bytes.');
  let after: string | null = null,
    existing: Extract<ResourceView, { kind: 'secret' }> | undefined;
  do {
    const search = new URLSearchParams({
      kind: 'secret',
      query: name,
      limit: '200',
      ...(after ? { after } : {}),
    });
    const page = await client.json('/api/principals/' + owner + '/resources?' + search, {}, listOf(Resource));
    existing = page.items.find(
      (item): item is Extract<ResourceView, { kind: 'secret' }> =>
        item.kind === 'secret' && item.name === name,
    );
    after = page.next;
  } while (after && !existing);
  const { custody } = privateClient(client);
  const previous = existing ? await custody.read(existing.id) : undefined;
  const environments = await Promise.all((args.values.for ?? []).map(id => custody.environment(Id.parse(id))));
  const policy = previous && !args.values.for ? previous.content.policy
    : await custody.policy(owner, 'secret', environments, { previous: previous?.content.policy });
  const result = await custody.save(name, content, policy, { previous });
  await output(result, args);
}

async function taskOutput(client: Client, task: TaskView, args: Arguments) {
  const result = await privateClient(client).custody.result(task);
  await output({ id: task.id, state: task.state, environmentId: task.environmentId,
    result: result?.result ?? null, error: result?.error ?? task.error }, args);
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
  if (command === 'agent' && args.positionals[0] === 'managed') return managedAgent();
  const client = new Client(await readIdentity(args.values.origin));
  const current = await client.session();
  if (!current.principal) throw new Error('The machine identity is no longer valid.');
  const owner = Id.parse(args.values.owner ?? current.principal.id);
  if (command === 'mcp') return startMcp(client);
  if (command === 'status') {
    const { wrappedKey: _wrappedKey, ...status } = current;
    await output(status, args);
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
      ownerId: owner, name: Name.parse(args.values.name ?? hostname()), callers: (args.values.caller ?? []).map(id => Id.parse(id)),
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
  if (command === 'connect') {
    const flowClient = connectionClient(client), action = args.positionals[0] ?? 'start';
    let progress: FlowProgress;
    if (action === 'start') progress = await startConnection(client, { ownerId: owner,
      environmentId: requireArgument(args.values.environment, 'Choose --environment ID.'),
      methodId: requireArgument(args.values.method, 'Choose --method ID.'), name: args.values.name,
      appId: args.values.app, connectionId: args.values.connection,
      fields: await json(args.values.fields, {}), scopes: await json(args.values.scopes, []),
      role: args.values.role ? await json(args.values.role) : undefined,
      environments: args.values.for, redirectUri: args.values['redirect-uri'] });
    else {
      const id = Id.parse(requireArgument(args.positionals[1], 'Supply a connection request ID.'));
      if (action === 'accept') progress = await flowClient.accept(id);
      else if (action === 'cancel') progress = await flowClient.cancel(id);
      else if (action === 'complete') {
        const value = await text(requireArgument(args.values.parameters, 'Supply the authorization response with --parameters.'));
        progress = await flowClient.complete(id, value.includes('://') ? new URL(value).search.slice(1) : value.replace(/^\?/, ''));
      } else if (action === 'status' || action === 'wait') progress = await flowClient.progress(id);
      else throw new Error('Choose connect start, status, wait, complete, accept, or cancel.');
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
    await taskOutput(client, await privateClient(client).custody.resume(id), args); return 0;
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
  if (command === 'run') {
    const environmentId = Id.parse(requireArgument(args.values.environment, 'Choose an explicit execution environment with --environment ID.'));
    const modes = [args.values.request, args.values.function, commandArguments.length ? true : false].filter(Boolean);
    if (modes.length !== 1) throw new Error('Choose --request, --function, or a command after --.');
    const fn = args.values.function ? await client.json('/api/resources/' + Id.parse(args.values.function), {}, Resource) : null;
    if (fn && fn.kind !== 'function') throw new Error('Choose a saved function.');
    const input = args.values.request
      ? { kind: 'http', request: await json(args.values.request) }
      : fn?.kind === 'function'
        ? {
            kind: 'function',
            definition: fn.data,
            arguments: await json(args.values.arguments, {}),
          }
        : {
            kind: 'command',
            command: commandArguments,
            timeoutSeconds: seconds(args.values.timeout, 60, 3600),
            inputs: await json(args.values.inputs, []),
          };
    const run = await privateClient(client).custody.submit(owner, environmentId, RuntimeOperation.parse(input), {
      save: z.record(z.string(), Name).parse(await json(args.values.save, {})),
    });
    const result = args.values.wait
      ? await waitFor(
          () => client.json('/api/executions/' + run.id, {}, Task),
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
      () => client.json('/api/executions/' + id, {}, Task),
      (value) => value.state,
      seconds(args.values.timeout, 3600),
    );
    await taskOutput(client, result, args);
    return result.state === 'succeeded' ? 0 : 1;
  }
  if (command === 'join' || command === 'request') {
    if (command === 'request' && args.positionals[0] === 'wait') {
      const id = Id.parse(requireArgument(args.positionals[1], 'Supply a request ID.'));
      const result = await waitFor(
        () => client.json('/api/requests/' + id, {}, ApprovalRequest),
        (value) => value.state,
        seconds(args.values.timeout, 1800),
      );
      await output(result, args);
      return result.state === 'approved' ? 0 : 1;
    }
    const input =
      command === 'join'
        ? {
            to: args.values.to,
            message: args.values.message ?? hostname(),
            operations: [
              {
                method: 'POST',
                path: '/api/relations',
                body: { subjectId: current.principal.id, relation: 'agent', principalId: '$approver' },
              },
            ],
          }
        : await json(requireArgument(args.values.body, 'Supply the request as --body JSON.'));
    const request = await client.json(
      '/api/requests',
      { method: 'POST', body: RequestInput.parse(input) },
      ApprovalRequest,
    );
    await output(request, args);
    if (args.values.wait) {
      const result = await waitFor(
        () => client.json('/api/requests/' + request.id, {}, ApprovalRequest),
        (value) => value.state,
        seconds(args.values.timeout, 1800),
      );
      await output(result, { ...args, values: { ...args.values, force: true } });
      return result.state === 'approved' ? 0 : 1;
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
