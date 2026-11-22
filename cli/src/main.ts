#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { hostname } from 'node:os';
import { open as openFile, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import packageInfo from '../package.json' with { type: 'json' };
import { Credential, Id, Input, Name, Resource, Sealed, listOf } from '../../shared/contracts.js';
import type { ResourceView } from '../../shared/contracts.js';
import { Session } from '../../shared/session.js';
import { IdentityKeys, newEncryptionKey, newIdentityKeys, open as openSealed, publicPart, unbase64url, unwrap } from '../../shared/encryption.js';
import { canonical } from '../../shared/digest.js';
import { Client, ApiError, UnreadableResponse } from './client.js';
import { configPath, listIdentities, origin, readIdentity, saveIdentity, secureWrite, useIdentity } from './config.js';
import { execute } from './execute.js';
import { localInputs, privateClient } from './custody.js';
import { RequestCreate, RequestView } from '../../shared/operations.js';
import { awaitRequestedConnection, chooseMethod, connectionInput, connectionOutput, connectionOwner, existingConnection, flowOutput,
  handedOver, ownerApplication, requestConnection } from './connections.js';
import type { OperationResultView } from '../../shared/operation-client.js';
import { connectionMethod } from '../../shared/connection-methods.js';
import { withConnectionKey } from './ssh-keys.js';
import { operationClient } from './operations.js';
import { releaseNote } from './releases.js';

const help = `Foundation ${packageInfo.version}

Usage: foundation <command> [options]

  login [--origin URL]                  Sign in by approving this machine in a browser
  login --key TOKEN [--origin URL]      Sign in with a key issued in a browser
  init --name NAME [--origin URL]       Register this machine as a new principal
  status                               Show this machine and the principals it may act for
  identity list                        List the identities saved on this machine
  identity use ID                      Make a saved identity the default
  request-access [--to ID] [--wait]     Ask another principal to delegate to this machine
  connect SERVICE [--owner ID] [--needs NAME] [--why TEXT] [--wait]
                                       Find a connection you can use, connect the service yourself when you may,
                                       or ask its owner
  connect SERVICE --field NAME=VALUE ... [--name NAME] [--owner ID]
                                       Make a connection with the values given, this machine's own unless
                                       --owner names another
  connect --connection ID [--scope NAME] [--wait]
                                       Connect a connection again, yourself when you may, or ask its owner
  connect wait ID                      Wait for the owner to finish a requested connection
  connect continue ID                  Finish a connection this machine started, or one a browser could not
                                       finish that this machine may make
  keep NAME (--file FILE | --stdin)    Seal and save a variable
  read ID [--output FILE]               Open a variable you may open
  exec --inputs JSON -- COMMAND ...    Give opened values to a local command
  seal                                 Seal what this machine opens for those let in since
  ssh-agent ID -- COMMAND ...          Run a command with an SSH connection's key in a temporary agent
  api METHOD /api/PATH [--body JSON]    Call the Foundation API; everything else is done this way

Options:
  --owner ID             The principal that owns a new item, or that connect asks (by default
                         the one delegating to this machine)
  --needs NAME           Output a requested connection must give, such as RUNPOD_API_KEY (repeatable)
  --method ID            Connection method a request asks for
  --connection ID        Connection to connect again
  --scope NAME           Service permission a connection asks for (repeatable; by default those it has)
  --app ID               Application a new connection is authorized through, when the owner has several
  --why TEXT             Why a connection is requested, shown to its owner
  --new                  Ask for another connection even if the owner has one
  --field NAME=VALUE     A value a connection is made with; give a secret as @FILE or @- (repeatable)
  --to ID                Principal asked for delegation
  --message TEXT         Message shown with a delegation request
  --principal ID         Act as this saved identity for one command
  --key TOKEN            A key issued in a browser (@FILE or @- to read it)
  --name NAME            How this machine appears when it signs in (default: host name), or the name of a
                         connection made with --field
  --origin URL           Choose a server when signing in or registering
  --inputs JSON          Inputs for exec (default: [])
  --wait                 Wait for the request to be answered
  --timeout SECONDS      Maximum waiting time
  --output FILE          Write the result to a private file
  --force                Replace an existing output file
  --body JSON            Request body for api
  --upload FILE          Send a binary body with api
  --help                 Show this help
  --version              Show the version

JSON and the key may be supplied as @FILE, or @- to read standard input.
Signing in makes this machine act as you, with your encryption key. Registering
with --name creates a separate principal instead.
The unlock portion of a sign-in key stays on this machine. Content is sealed for
everyone Foundation lets open it, and readable only by them. exec opens values on
this machine and masks them in stdout and stderr. read deliberately reveals
content. Ctrl+C while waiting stops the wait; the request stays.

Identity: $XDG_CONFIG_HOME/foundation/identity.json (defaults to ~/.config)
It can hold several identities. A command acts as --principal, then
FOUNDATION_PRINCIPAL_ID, then the default chosen with identity use.
Environment identity: FOUNDATION_ORIGIN, FOUNDATION_TOKEN,
FOUNDATION_PRINCIPAL_ID, FOUNDATION_PRIVATE_KEYS. The last is base64url-encoded
JSON; omit it for metadata-only access.
`;
const textOption = { type: 'string' as const },
  booleanOption = { type: 'boolean' as const };
const options = {
  name: textOption,
  key: textOption,
  origin: textOption,
  owner: textOption,
  principal: textOption,
  to: textOption,
  message: textOption,
  body: textOption,
  file: textOption,
  stdin: booleanOption,
  method: textOption,
  connection: textOption,
  needs: { type: 'string' as const, multiple: true as const },
  field: { type: 'string' as const, multiple: true as const },
  scope: { type: 'string' as const, multiple: true as const },
  app: textOption,
  why: textOption,
  new: booleanOption,
  inputs: textOption,
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
// The values a connection is made with, each given as NAME=VALUE.
async function fieldValues(entries: string[]) {
  const fields: Record<string, string> = {};
  for (const entry of entries) {
    const at = entry.indexOf('=');
    if (at < 1) throw new Error('Give each --field as NAME=VALUE.');
    const name = entry.slice(0, at);
    if (Object.hasOwn(fields, name)) throw new Error('Give the field ' + name + ' once.');
    fields[name] = await text(entry.slice(at + 1));
  }
  return fields;
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
  const keys = IdentityKeys.parse(await unwrap(current.wrappedKey, unbase64url(unlock), current.principal.id).catch(() => {
    throw new Error('The encryption key could not be unlocked with this key.');
  }));
  if (!current.principal.publicKey || canonical(publicPart(keys.encryption)) !== canonical(current.principal.publicKey))
    throw new Error('This key carries an earlier encryption key of the principal. Issue a new key from a browser.');
  await saveIdentity({ origin: base, principalId: current.principal.id, token, keys });
  print({ principal: { id: current.principal.id, name: current.principal.name }, origin: base, identity: configPath() });
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
  await saveIdentity({ origin: base, principalId: registered.principal.id, token: registered.token, keys });
  print({ principal: registered.principal, origin: base, identity: path });
}
async function identity(args: Arguments) {
  const action = args.positionals[0];
  if (action === 'use') {
    const principalId = Id.parse(requireArgument(args.positionals[1], 'Supply a principal ID.'));
    await useIdentity(principalId);
    print({ current: principalId, identity: configPath() });
    return;
  }
  if (action !== 'list') throw new Error('Use foundation identity list or foundation identity use ID.');
  const items = await Promise.all((await listIdentities()).map(async ({ current, ...saved }) => {
    const session = await new Client(saved).session().catch(() => null);
    return { principalId: saved.principalId, name: session?.principal?.name ?? null, origin: saved.origin, current };
  }));
  await output(items, args);
}
async function waitFor<T>(fetcher: () => Promise<T>, state: (value: T) => string, timeout: number) {
  const deadline = Date.now() + timeout * 1000;
  while (true) {
    const value = await fetcher();
    if (state(value) !== 'pending') return value;
    if (Date.now() >= deadline)
      throw new Error('The request is still pending. Run the wait command again to continue.');
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
  // The value is sealed on this machine for everyone Foundation lists as able to open it.
  const { custody } = await privateClient(client), previous = existing ? await custody.latest(existing.id) : undefined;
  await output(await custody.save({ id: existing?.id ?? randomUUID(), ownerId: owner, kind: 'variable' }, name, content,
    { previous }), args);
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
  if (command === 'identity') {
    await identity(args);
    return 0;
  }
  const client = new Client(await readIdentity(args.values.origin, args.values.principal));
  const self = client.identity.principalId, owner = Id.parse(args.values.owner ?? self);
  if (command === 'status') {
    const { wrappedKey: _wrappedKey, ...status } = await client.session();
    await output(status, args);
    return 0;
  }
  if (command === 'connect') {
    // Goes on with a connection this machine makes until it is made, the service is still to be allowed after the
    // waiting time, or it fails.
    const finish = async (operations: Awaited<ReturnType<typeof operationClient>>, started: OperationResultView, wait: boolean) => {
      let progress = started;
      const deadline = Date.now() + seconds(args.values.timeout, 600) * 1000;
      while (wait && 'flow' in progress && (progress.kind === 'pending' || progress.kind === 'authorize') && Date.now() < deadline) {
        await delay(1000);
        progress = await operations.connections.progress(progress.flow.id);
      }
      await output('flow' in progress ? flowOutput(progress) : 'kind' in progress && progress.kind === 'saved'
        ? { kind: 'connected', id: progress.operationId, connectionId: progress.resource.id } : progress, args);
      return 'flow' in progress ? ['connected'].includes(progress.kind) || !wait && progress.kind === 'authorize' ? 0 : 1
        : 'kind' in progress && progress.kind === 'saved' ? 0 : 1;
    };
    if (args.positionals[0] === 'continue') {
      // A service that gives its tokens only outside a browser: this machine exchanges and seals them. A connection a
      // browser started and could not finish, this machine makes again itself when it may make it.
      const operations = await operationClient(client);
      const id = Id.parse(requireArgument(args.positionals[1], 'Supply the operation ID.'));
      const operation = await operations.get(id);
      if (operation.actor.id === self) return finish(operations, await operations.continue(id), true);
      const method = (await chooseMethod(client, { methodId: z.object({ methodId: z.string() }).parse(operation.input).methodId,
        needs: [] })).method;
      const input = handedOver(operation, method);
      if (!(input.connectionId
        ? (await client.json('/api/resources/' + input.connectionId, {}, Resource)).permissions.includes('update')
        : (await client.session()).principals.some(principal => principal.id === input.ownerId && principal.createKinds.includes('connection'))))
        throw new Error('This machine may not make this connection. Finish it signed in as ' + operation.actor.name + '.');
      return finish(operations, await operations.perform({ name: 'connection.connect', input }), !!args.values.wait);
    }
    if (args.positionals[0] === 'wait') {
      const request = await client.json('/api/requests/' + Id.parse(requireArgument(args.positionals[1], 'Supply a request ID.')), {}, RequestView);
      const result = await awaitRequestedConnection(client, request, seconds(args.values.timeout, 1800));
      await output(result, args);
      return result.kind === 'connected' ? 0 : 1;
    }
    // A machine that may make the connection makes it itself, through a method it authorizes at the service, and a
    // person only allows it there. Otherwise the owner is asked, and connects the service in a browser.
    const service = args.positionals[0], needs = args.values.needs ?? [];
    const again = args.values.connection ? await client.json('/api/resources/' + Id.parse(args.values.connection), {}, Resource) : null;
    if (again && again.kind !== 'connection') throw new Error('Choose a connection to connect again.');
    if (!service && !args.values.method && !again) throw new Error('Name a service, such as foundation connect cloudrift.');
    // Values given here make a connection of this machine's own, unless it is made for another owner or again.
    const fields = args.values.field?.length ? await fieldValues(args.values.field) : null;
    const current = await client.session();
    const connectionOwnerId = again ? again.ownerId : fields ? owner : await connectionOwner(client, self, args.values.owner);
    const connectionOwnerView = current.principals.find(principal => principal.id === connectionOwnerId);
    const mayMake = again ? again.permissions.includes('update') : !!connectionOwnerView?.createKinds.includes('connection');
    const methodId = args.values.method ?? (again?.kind === 'connection' ? again.data.methodId : undefined);
    let chosen = await chooseMethod(client, { service, methodId, needs, making: mayMake && !fields });
    const wanted = needs.length ? needs : connectionMethod(chosen.method).outputs;
    const found = args.values.new || again || fields ? null
      : await existingConnection(client, { owner: connectionOwnerId, canListOwner: !!connectionOwnerView,
        service: chosen.service, outputs: wanted });
    if (found) {
      await output({ kind: 'existing', ...connectionOutput(found), next: 'Use this connection, or add --new to ask for another.' }, args);
      return 0;
    }
    // Values given here are sealed on this machine into the connection it makes.
    if (fields) {
      if (!mayMake) throw new Error('This machine may not make this connection. Leave out --field to ask its owner.');
      const operations = await operationClient(client);
      const input = connectionInput({ ownerId: connectionOwnerId, method: chosen.method,
        name: args.values.name ?? again?.name ?? chosen.method.defaultName, connectionId: again?.id });
      return finish(operations, await operations.perform({ name: 'connection.connect', input }, { fields }), false);
    }
    if (mayMake && connectionMethod(chosen.method).browserAuthorization) {
      const appId = !connectionMethod(chosen.method).requiresApp ? null
        : again?.kind === 'connection' && again.data.appId && !args.values.app ? again.data.appId
        : await ownerApplication(client, connectionOwnerId, chosen.method, args.values.app);
      if (appId !== undefined) {
        const operations = await operationClient(client);
        const input = connectionInput({ ownerId: connectionOwnerId, method: chosen.method, name: again?.name ?? chosen.method.defaultName,
          connectionId: again?.id, appId, scopes: args.values.scope ?? (again?.kind === 'connection' ? again.data.scopes : undefined),
          fields: again?.kind === 'connection' ? again.data.fields : undefined });
        return finish(operations, await operations.perform({ name: 'connection.connect', input }), !!args.values.wait);
      }
      // Without an application of the owner's to authorize through, the owner is asked for a connection it can make.
      if (!again && !args.values.method) chosen = await chooseMethod(client, { service, needs });
    }
    const request = await requestConnection(client, { owner: connectionOwnerId, method: chosen.method, why: args.values.why,
      connectionId: again?.id, userId: connectionOwnerView?.permissions.includes('use') ? undefined : self });
    await output({ kind: 'requested', requestId: request.id, to: request.to,
      method: chosen.method.id, outputs: connectionMethod(chosen.method).outputs, url: request.url, expiresAt: request.expiresAt,
      next: 'Give the URL to ' + (request.to?.name ?? 'the owner') + ', then run foundation connect wait ' + request.id }, args);
    if (!args.values.wait) return 0;
    const result = await awaitRequestedConnection(client, request, seconds(args.values.timeout, 1800));
    await output(result, { ...args, values: { ...args.values, force: true } });
    return result.kind === 'connected' ? 0 : 1;
  }
  if (command === 'api') {
    const method = requireArgument(args.positionals[0], 'Supply an HTTP method.').toUpperCase();
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method))
      throw new Error('Choose GET, HEAD, POST, PUT, PATCH, or DELETE.');
    const path = requireArgument(args.positionals[1], 'Supply an API path beginning with /api/.');
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
    const bytes = await (await privateClient(client)).custody.reveal(id);
    if (args.values.output) await secureWrite(args.values.output, bytes, !!args.values.force);
    else process.stdout.write(bytes);
    return 0;
  }
  if (command === 'seal') {
    const result = await (await privateClient(client)).custody.reprotectPending();
    await output(result, args);
    return result.failed.length ? 1 : 0;
  }
  if (command === 'ssh-agent') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply the SSH connection ID.'));
    if (!commandArguments.length) throw new Error('Put the command after --.');
    return withConnectionKey(client, id, (socket, place) => new Promise<number>((resolveCode, reject) => {
      const child = spawn(commandArguments[0]!, commandArguments.slice(1), { stdio: 'inherit',
        env: { ...process.env, ...place, SSH_AUTH_SOCK: socket } });
      child.once('error', () => reject(new Error('The command could not be started. Check the executable and arguments.')));
      child.once('close', (code, signal) => resolveCode(code ?? (signal === 'SIGINT' ? 130 : 1)));
    }));
  }
  if (command === 'exec') {
    const inputs = z
      .array(Input)
      .max(32)
      .parse(await json(args.values.inputs, []));
    return execute(await localInputs(client, inputs), commandArguments);
  }
  if (command === 'request-access') {
    const request = await client.json('/api/requests', { method: 'POST', body: RequestCreate.parse({
      to: args.values.to, message: args.values.message ?? hostname(),
      operations: [{ name: 'relation.draw', input: { subjectId: self, relation: 'delegate', objectId: '$approver' } }],
    }) }, RequestView);
    await output(request, args);
    if (!args.values.wait) return 0;
    const result = await waitFor(() => client.json('/api/requests/' + request.id, {}, RequestView), value => value.state,
      seconds(args.values.timeout, 1800));
    await output(result, { ...args, values: { ...args.values, force: true } });
    return result.state === 'approved' ? 0 : 1;
  }
  throw new Error('Unknown command: ' + command + '. Run foundation --help.');
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  // A server that was released with another CLI says which one, so that a mismatch is not mistaken for another fault.
  const answered = error instanceof ApiError || error instanceof UnreadableResponse ? error.origin : undefined;
  const note = answered ? await releaseNote(answered, packageInfo.version) : null;
  const message =
    error instanceof ApiError
      ? error.code + ': ' + error.message + (error.details === undefined ? '' : '\n' + JSON.stringify(error.details))
      : error instanceof UnreadableResponse
        ? error.message + (note ? '' : '\n' + z.prettifyError(error.error))
      : error instanceof z.ZodError
        ? 'Check the command inputs.'
        : error instanceof Error
          ? error.message
          : 'The command failed.';
  process.stderr.write('foundation: ' + message + (note ? '\n' + note : '') + '\n');
  process.exitCode = 1;
}
