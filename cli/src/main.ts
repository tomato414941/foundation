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
  NewResource,
  PublicKey,
  Recipient,
  RequestInput,
  Resource,
  Run,
  RunInput,
  Sealed,
  listOf,
} from '../../shared/contracts.js';
import type { ResourceView } from '../../shared/contracts.js';
import { Session } from '../../shared/session.js';
import { encode, newEncryptionKey, open, seal, unwrap } from '../../shared/encryption.js';
import { Client, ApiError } from './client.js';
import { configPath, origin, readIdentity, saveIdentity, secureWrite } from './config.js';
import type { IdentityConfig } from './config.js';
import { execute } from './execute.js';

const help = `Foundation ${packageInfo.version}

Usage: foundation <command> [options]

  init --key TOKEN [--origin URL]       Sign in with a key you issued and save it
  init --name NAME [--origin URL]       Register this machine as a new principal
  status                               Show this machine and its accessible principals
  join [--to ID] [--wait]               Ask a person to take on this machine
  api METHOD /api/PATH [--body JSON]    Call the common Foundation API
  schema [--output FILE]                Read the OpenAPI specification
  keep NAME (--file FILE | --stdin)    Encrypt and save a secret
  read ID [--output FILE]               Decrypt a secret you can reveal
  exec --inputs JSON -- COMMAND ...    Deliver inputs to a local command
  run --request JSON [--save JSON]      Run an HTTP request
  run --function ID [--arguments JSON] Run a saved function
  run --environment ID -- COMMAND ...  Run a command in an environment
  wait ID [--timeout SECONDS]           Wait for a run to finish
  request --body JSON                  Create an approval request
  request wait ID [--timeout SECONDS]  Wait for an approval request
  export --output FILE                 Download an encrypted account export

Options:
  --owner ID             Choose the principal that owns a new item or run
  --key TOKEN            A key issued from a browser (@FILE or @- to read it)
  --origin URL           Choose a server when initializing a machine
  --allow-use            Allow Foundation to use a saved secret in runs
  --no-allow-use         Turn off use when updating a secret
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
New secrets require --allow-use to be delivered to commands. Updates retain the
current setting unless --allow-use or --no-allow-use is supplied.
exec masks input values in stdout and stderr. read deliberately reveals content.
Ctrl+C while waiting stops the wait; use the API to cancel the remote operation.

Identity: $XDG_CONFIG_HOME/foundation/identity.json (defaults to ~/.config)
Environment identity: FOUNDATION_ORIGIN, FOUNDATION_TOKEN,
FOUNDATION_PRINCIPAL_ID, FOUNDATION_PRIVATE_KEY (base64url-encoded private JWK).
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
  'allow-use': booleanOption,
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
    const token = (await text(args.values.key)).trim();
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
    const privateKey = await unwrap(current.wrappedKey, encode(token), current.principal.id).catch(() => {
      throw new Error('The encryption key could not be unlocked with this key.');
    });
    await saveIdentity({ origin: base, principalId: current.principal.id, token, privateKey: privateKey as IdentityConfig['privateKey'] });
    print({ principal: { id: current.principal.id, name: current.principal.name }, origin: base, identity: path });
    return;
  }
  const name = Name.parse(args.values.name || hostname()),
    keys = await newEncryptionKey();
  let response: Response;
  try {
    response = await fetch(base + '/api/auth/enroll', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, publicKey: keys.publicKey }),
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
  await saveIdentity({
    origin: base,
    principalId: registered.principal.id,
    token: registered.token,
    privateKey: keys.privateKey as { kty: 'EC'; crv: 'P-256'; x: string; y: string; d: string },
  });
  print({ principal: registered.principal, origin: base, identity: path });
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
  const current = await client.session();
  const id = existing?.id ?? randomUUID(),
    allowUse = args.values['allow-use'] ?? existing?.data.allowUse ?? false;
  const recipients = (
    await client.json(
      existing ? `/api/resources/${id}/recipients` : `/api/principals/${owner}/recipients`,
      {},
      listOf(Recipient),
    )
  ).items;
  for (const recipientId of existing?.data.recipients ?? [])
    if (recipientId !== current.server.id && !recipients.some((recipient) => recipient.id === recipientId)) {
      const recipient = await client.json(
        '/api/identities/' + recipientId,
        {},
        z.object({ id: Id, name: Name, publicKey: PublicKey.nullable() }),
      );
      if (recipient.publicKey) recipients.push({ ...recipient, publicKey: recipient.publicKey });
    }
  if (allowUse) recipients.push(current.server);
  const sealed = await seal(content, recipients, 'resource:' + id);
  const result = existing
    ? await client.json(
        '/api/resources/' + id,
        {
          method: 'PATCH',
          body: { version: existing.version, name, sealed, bytes: content.length, allowUse },
        },
        Resource,
      )
    : await client.json(
        '/api/principals/' + owner + '/resources',
        {
          method: 'POST',
          body: NewResource.parse({ kind: 'secret', id, name, sealed, bytes: content.length, allowUse }),
        },
        Resource,
      );
  await output(result, args);
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
  const client = new Client(await readIdentity(args.values.origin));
  const current = await client.session();
  if (!current.principal) throw new Error('The machine identity is no longer valid.');
  const owner = Id.parse(args.values.owner ?? current.principal.id);
  if (command === 'status') {
    const { wrappedKey: _wrappedKey, ...status } = current;
    await output(status, args);
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
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply the secret ID.')),
      content = await client.json(
        '/api/resources/' + id + '/secret',
        {},
        z.object({ sealed: Sealed, context: z.string() }),
      );
    const bytes = await open(
      content.sealed,
      client.identity.privateKey,
      current.principal.id,
      content.context,
    );
    if (args.values.output) await secureWrite(args.values.output, bytes, !!args.values.force);
    else process.stdout.write(bytes);
    return 0;
  }
  if (command === 'exec') {
    const inputs = z
      .array(Input)
      .max(32)
      .parse(await json(args.values.inputs, []));
    return execute(client, inputs, commandArguments);
  }
  if (command === 'run') {
    const modes = [args.values.request, args.values.function, args.values.environment].filter(Boolean);
    if (modes.length !== 1) throw new Error('Choose one of --request, --function, or --environment.');
    const input = args.values.request
      ? { kind: 'http', request: await json(args.values.request), save: await json(args.values.save, {}) }
      : args.values.function
        ? {
            kind: 'function',
            functionId: args.values.function,
            arguments: await json(args.values.arguments, {}),
          }
        : {
            kind: 'command',
            environmentId: args.values.environment,
            command: commandArguments,
            timeoutSeconds: seconds(args.values.timeout, 60, 3600),
            inputs: await json(args.values.inputs, []),
          };
    const run = await client.json(
      '/api/principals/' + owner + '/runs',
      { method: 'POST', body: RunInput.parse(input) },
      Run,
    );
    const result = args.values.wait
      ? await waitFor(
          () => client.json('/api/runs/' + run.id, {}, Run),
          (value) => value.state,
          seconds(args.values.timeout, 3600),
        )
      : run;
    await output(result, args);
    return result.state === 'failed' || result.state === 'cancelled' ? 1 : 0;
  }
  if (command === 'wait') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply a run ID.'));
    const result = await waitFor(
      () => client.json('/api/runs/' + id, {}, Run),
      (value) => value.state,
      seconds(args.values.timeout, 3600),
    );
    await output(result, args);
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
