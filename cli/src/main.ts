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
import { bindKeys, fingerprint, newIdentityKeys, PrivateKeys, signBinding, SignedBinding } from '../../shared/authority.js';
import { Task } from '../../shared/runtime-protocol.js';
import type { TaskView } from '../../shared/runtime-protocol.js';
import { Client, ApiError } from './client.js';
import { currentIdentity, rotateIdentity } from './keys.js';
import { configPath, listIdentities, origin, readIdentity, saveIdentity, secureWrite, useIdentity } from './config.js';
import { execute } from './execute.js';
import { localInputs, privateClient } from './custody.js';
import { IdentityVerificationRequired, transferResource } from '../../shared/client.js';
import { launchAgent } from './agent-launcher.js';
import { executionClient } from './executions.js';
import { ExecutionInput, ExecutionResponse, Invocation, DefinitionDescription, Execution } from '../../shared/executions.js';
import { OperationMaterial } from '../../shared/execution-client.js';
import { startMcp } from './mcp.js';
import { FunctionClient } from '../../shared/function-client.js';
import { FunctionDefinition } from '../../shared/contracts.js';
import { awaitRequestedConnection, chooseMethod, connectionClient, connectionOutput, connectionOwner, existingConnection, flowOutput,
  requestConnection, saveApp, startConnection } from './connections.js';
import { connectionMethod } from '../../shared/connection-methods.js';
import { newSSHKey, sshAccess, withStoredKey } from './ssh-access.js';
import type { FlowProgress } from '../../shared/connection-client.js';

const help = `Foundation ${packageInfo.version}

Usage: foundation <command> [options]

  login [--origin URL]                  Sign in by approving this machine in a browser
  login --key TOKEN [--origin URL]      Sign in with a key issued in a browser
  init --name NAME [--origin URL]       Register this machine as a new principal
  status                               Show this machine and its accessible principals
  identity list                        List the identities saved on this machine
  identity use ID                      Make a saved identity the default
  request-access [--to ID] [--wait]     Ask another principal to delegate access to this machine
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
  keys rotate                          Replace this identity's keys, keeping its items and sign-ins
  agent start [--id ID]                Register this machine as an execution environment
  app NAME --method ID --client-id ID  Encrypt an application (--for ENV to allow use)
  connect SERVICE [--needs NAME] [--why TEXT] Ask the owner to connect a service in a browser,
                                       or return their ready connection that gives NAME
  connect --method ID --fields JSON    Encrypt and save a connection on this device
  connect wait ID                      Continue after service authorization
  connect wait-request ID              Wait for the owner to finish a requested connection
  keep NAME (--file FILE | --stdin)    Encrypt and save a variable (--for ENV to allow execution)
  transfer ID --to ID                  Transfer an item after the recipient accepts it
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
  ssh-key create NAME (--store | --private-key-output FILE) Make an SSH key and register its public key
  ssh-key add NAME (--public-key KEY | --private-key FILE) Register an existing SSH key
  ssh-key revoke ID                    Take an SSH key out of every host and keep it out
  ssh-key agent ID -- COMMAND ...      Run a command with a stored SSH key in a temporary agent
  ssh-host add NAME --address HOST --host-key KEY Register a host with its verified OpenSSH host public keys
  ssh-access grant --host ID --ssh-key ID --account NAME Let a key into a host account
  ssh-access revoke ID                 Take a key out of a host account
  ssh-access list [--host ID] [--ssh-key ID] [--status STATUS] Show where keys are let in
  ssh-access apply ID [--account NAME] Apply a host's authorized keys over SSH and verify them
  ssh-access check ID [--account NAME] Read a host's authorized keys over SSH and report them

Options:
  --owner ID             Choose the principal that owns a new item or run (for connect without
                         --fields: the principal asked, by default the one delegating to this machine)
  --needs NAME           Output a requested connection must give, such as RUNPOD_API_KEY (repeatable)
  --why TEXT             Why a connection is requested, shown to its owner
  --new                  Ask for another connection even if the owner has one
  --to ID                Principal receiving a transfer or access request
  --principal ID         Act as this saved identity for one command
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
  --confirmation ID      Send the api command with a confirmation proved through the confirmation API
  --store                Keep the new SSH private key encrypted in Foundation
  --public-key KEY       SSH public key text (@FILE accepted)
  --private-key FILE     SSH private key file to keep encrypted in Foundation
  --private-key-output FILE  Write a new SSH private key to this private file on this machine
  --purpose TEXT         What an SSH key is for
  --address HOST         SSH host name or IP address
  --port PORT            SSH port (default: 22)
  --host-key KEY         The server's OpenSSH host public key, such as ssh-ed25519 AAAA..., verified with its
                         administrator or console (@FILE accepted, repeatable)
  --authorized-keys-file PATH  Authorized keys file, relative to the home directory (default: .ssh/authorized_keys)
  --host ID              SSH host
  --ssh-key ID           SSH key; for apply and check, sign in with its private key kept in Foundation
  --account NAME         Account on the SSH host
  --expires TIME         When an SSH authorization ends (ISO 8601)
  --from PATTERNS        Hosts an SSH key is accepted from, comma-separated
  --status STATUS        applied, pending, removed, or remains_unmanaged
  --identity FILE        Sign in to the SSH host with this private key file
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
It can hold several identities. A command acts as --principal, then
FOUNDATION_PRINCIPAL_ID, then the default chosen with identity use.
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
  principal: textOption,
  to: textOption,
  message: textOption,
  body: textOption,
  confirmation: textOption,
  file: textOption,
  stdin: booleanOption,
  for: { type: 'string' as const, multiple: true as const },
  fingerprint: textOption,
  id: textOption,
  isolation: textOption,
  image: textOption,
  once: booleanOption,
  method: textOption,
  needs: { type: 'string' as const, multiple: true as const },
  why: textOption,
  new: booleanOption,
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
  store: booleanOption,
  'public-key': textOption,
  'private-key': textOption,
  'private-key-output': textOption,
  purpose: textOption,
  address: textOption,
  port: textOption,
  'host-key': { type: 'string' as const, multiple: true as const },
  'authorized-keys-file': textOption,
  host: textOption,
  'ssh-key': textOption,
  account: textOption,
  expires: textOption,
  from: textOption,
  status: textOption,
  identity: textOption,
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
    keys = await newIdentityKeys(),
    binding = bindKeys(randomUUID(), keys);
  let response: Response;
  try {
    // The identity is registered with the keys it signed for itself, so that nothing else sets them first.
    response = await fetch(base + '/api/auth/enroll', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, binding: await signBinding(binding, keys) }),
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
  if (registered.principal.id !== binding.principalId) throw new Error('Foundation registered a different identity.');
  await saveIdentity({ origin: base, principalId: registered.principal.id, token: registered.token, keys, binding });
  print({ principal: registered.principal, origin: base, identity: path, fingerprint: await fingerprint(binding) });
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

// Saves a private key as a new variable of the owner, failing when one of that name exists, and registers the SSH
// key with it. When registering fails, the variable just made is removed again.
async function withNewVariable(client: Client, owner: string, name: string, content: Uint8Array,
  register: (variableId: string) => Promise<ResourceView>) {
  const completed = await executionClient(client).execute({ name: 'variable.save', input: { ownerId: owner, name } }, { value: content });
  if (!('kind' in completed) || completed.kind !== 'saved') throw new Error('Finish saving the variable.');
  const variable = completed.resource;
  try { return await register(variable.id); } catch (error) {
    await client.json('/api/resources/' + variable.id, { method: 'DELETE' }).catch(() => process.stderr.write(
      'foundation: the private key was saved as variable ' + variable.id + ', which could not be removed after the SSH key failed to register.\n'));
    throw error;
  }
}
// The public key a private key file holds, as OpenSSH reads it; a key protected by a passphrase is refused.
async function derivedPublicKey(file: string) {
  return new Promise<string>((resolveKey, reject) => {
    const child = spawn('ssh-keygen', ['-y', '-P', '', '-f', file], { stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.once('error', () => reject(new Error('Install OpenSSH to read the private key.')));
    child.once('close', code => code === 0 ? resolveKey(stdout.trim())
      : reject(new Error('Use an SSH private key file without a passphrase.')));
  });
}
async function sshKeyCommand(client: Client, args: Arguments, owner: string, commandArguments: string[]) {
  const action = requireArgument(args.positionals[0], 'Choose create, add, revoke, or agent.');
  const purpose = args.values.purpose ?? '';
  const register = (name: string, publicKey: string, privateKeyId: string | null) => client.json('/api/principals/' + owner + '/ssh-keys',
    { method: 'POST', body: { name, publicKey, purpose, privateKeyId } }, Resource);
  if (action === 'create') {
    const name = Name.parse(requireArgument(args.positionals[1], 'Supply the SSH key name.'));
    const keyFile = args.values['private-key-output'];
    if (Boolean(args.values.store) === Boolean(keyFile))
      throw new Error('Choose --store to keep the private key in Foundation or --private-key-output FILE to keep it on this machine.');
    if (keyFile && args.values.output && resolve(keyFile) === resolve(args.values.output))
      throw new Error('Write the private key and the result to different files.');
    const key = newSSHKey();
    if (keyFile) {
      await secureWrite(keyFile, key.privateKey, !!args.values.force);
      // A private key whose public key was not registered is of no use, so it does not stay behind.
      return register(name, key.publicKey, null).catch(async (error: unknown) => { await rm(keyFile, { force: true }); throw error; });
    }
    return withNewVariable(client, owner, name, Buffer.from(key.privateKey), id => register(name, key.publicKey, id));
  }
  if (action === 'add') {
    const name = Name.parse(requireArgument(args.positionals[1], 'Supply the SSH key name.'));
    if (Boolean(args.values['public-key']) === Boolean(args.values['private-key']))
      throw new Error('Choose --public-key KEY to register only the public key or --private-key FILE to keep the private key as well.');
    if (args.values['public-key']) return register(name, (await text(args.values['public-key'])).trim(), null);
    const file = args.values['private-key']!, publicKey = await derivedPublicKey(file);
    return withNewVariable(client, owner, name, await readFile(file), id => register(name, publicKey, id));
  }
  const id = Id.parse(requireArgument(args.positionals[1], 'Supply the SSH key ID.'));
  if (action === 'revoke') return client.json('/api/ssh-keys/' + id + '/revoke', { method: 'POST', body: {} }, Resource);
  if (action === 'agent') {
    if (!commandArguments.length) throw new Error('Put the command after --.');
    return withStoredKey(client, id, agent => new Promise<number>((resolveCode, reject) => {
      const child = spawn(commandArguments[0]!, commandArguments.slice(1), { stdio: 'inherit', env: { ...process.env, SSH_AUTH_SOCK: agent.socket } });
      child.once('error', () => reject(new Error('The command could not be started. Check the executable and arguments.')));
      child.once('close', (code, signal) => resolveCode(code ?? (signal === 'SIGINT' ? 130 : 1)));
    }));
  }
  throw new Error('Choose create, add, revoke, or agent.');
}
async function sshHostCommand(client: Client, args: Arguments, owner: string) {
  if (args.positionals[0] !== 'add') throw new Error('Use foundation ssh-host add.');
  const name = Name.parse(requireArgument(args.positionals[1], 'Supply the SSH host name.'));
  const hostKeys = await Promise.all((args.values['host-key'] ?? []).map(async value => (await text(value)).trim()));
  if (!hostKeys.length) throw new Error("Supply the server's OpenSSH host public keys, verified with its administrator or console, with --host-key.");
  return client.json('/api/principals/' + owner + '/ssh-hosts', { method: 'POST', body: {
    name, address: requireArgument(args.values.address, 'Supply the host address with --address.'), hostKeys,
    ...(args.values.port ? { port: Number(args.values.port) } : {}),
    ...(args.values['authorized-keys-file'] ? { authorizedKeysFile: args.values['authorized-keys-file'] } : {}),
  } }, Resource);
}
function time(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error('Use an ISO 8601 time, such as 2026-12-31T00:00:00Z.');
  return parsed.toISOString();
}
async function sshAccessCommand(client: Client, args: Arguments) {
  const action = requireArgument(args.positionals[0], 'Choose grant, revoke, list, apply, or check.');
  if (action === 'grant') return client.json('/api/ssh-access', { method: 'POST', body: {
    hostId: Id.parse(requireArgument(args.values.host, 'Choose the host with --host ID.')),
    keyId: Id.parse(requireArgument(args.values['ssh-key'], 'Choose the key with --ssh-key ID.')),
    account: requireArgument(args.values.account, 'Choose the account with --account NAME.'),
    ...(args.values.expires ? { expiresAt: time(args.values.expires) } : {}),
    ...(args.values.from ? { from: args.values.from } : {}),
  } });
  if (action === 'list') return client.json('/api/ssh-access?' + new URLSearchParams({
    ...(args.values.host ? { hostId: args.values.host } : {}), ...(args.values['ssh-key'] ? { keyId: args.values['ssh-key'] } : {}),
    ...(args.values.status ? { status: args.values.status } : {}) }));
  const id = Id.parse(requireArgument(args.positionals[1], action === 'revoke' ? 'Supply the authorization ID.' : 'Supply the host ID.'));
  if (action === 'revoke') return client.json('/api/ssh-access/' + id, { method: 'DELETE' });
  if (action !== 'apply' && action !== 'check') throw new Error('Choose grant, revoke, list, apply, or check.');
  return sshAccess(client, id, { check: action === 'check', ...(args.values.account ? { account: args.values.account } : {}),
    ...(args.values.identity ? { identity: resolve(args.values.identity) } : {}),
    ...(args.values['ssh-key'] ? { keyId: Id.parse(args.values['ssh-key']) } : {}) });
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
  if (command === 'identity') {
    await identity(args);
    return 0;
  }
  const client = new Client(await currentIdentity(await readIdentity(args.values.origin, args.values.principal)));
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
  if (command === 'keys') {
    if (args.positionals[0] !== 'rotate') throw new Error('Use foundation keys rotate.');
    await output(await rotateIdentity(client.identity), args);
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
      try {
        const { done, failed } = await custody.reprotectPending();
        if (done.length) process.stderr.write('Encrypted ' + done.length + ' existing item(s) for their verified recipients.\n');
        if (failed.length) process.stderr.write(failed.length + ' item(s) still need an access update; run trust again after verifying the remaining keys or resolving the item errors.\n');
      } catch (error) {
        process.stderr.write('The public keys are verified, but existing items could not be updated: ' +
          (error instanceof Error ? error.message : String(error)) + '\nRun trust again to retry the update.\n');
      }
      await output({ identityId: id, fingerprint: identity.fingerprint, trusted: true }, args);
    }
    return 0;
  }
  if (command === 'agent') {
    if (args.positionals[0] !== 'start') throw new Error('Use foundation agent start.');
    return launchAgent('start', { origin: client.identity.origin, id: args.values.id ? Id.parse(args.values.id) : undefined,
      ownerId: owner, name: Name.parse(args.values.name ?? hostname()),
      isolation: z.enum(['process', 'container']).parse(args.values.isolation ?? 'process'),
      image: args.values.image, once: args.values.once });
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
    const flowClient = connectionClient(client), actions = ['start', 'status', 'wait', 'complete', 'cancel', 'wait-request'];
    const service = args.positionals[0] && !actions.includes(args.positionals[0]) ? args.positionals[0] : undefined;
    const action = service ? 'start' : args.positionals[0] ?? 'start';
    if (action === 'wait-request') {
      const request = await client.json('/api/requests/' + Id.parse(requireArgument(args.positionals[1], 'Supply a request ID.')), {}, ApprovalRequest);
      const result = await awaitRequestedConnection(client, request, seconds(args.values.timeout, 1800));
      await output(result, args);
      return result.kind === 'connected' ? 0 : 1;
    }
    // Without the values themselves, the owner is asked to enter them in a browser instead.
    if (action === 'start' && args.values.fields === undefined && args.values.aws === undefined) {
      const needs = args.values.needs ?? [];
      const chosen = service || needs.length || args.values.method
        ? await chooseMethod(client, { service, methodId: args.values.method, needs }) : null;
      if (!chosen) throw new Error('Name a service, such as foundation connect cloudrift, or choose --method ID.');
      if (service || chosen.method.registration.kind === 'input') {
        const connectionOwnerId = await connectionOwner(client, current.principal.id, args.values.owner);
        const wanted = needs.length ? needs : connectionMethod(chosen.method).outputs;
        const found = args.values.new || args.values.connection ? null
          : await existingConnection(client, connectionOwnerId, chosen.service, wanted);
        if (found) {
          await output({ kind: 'existing', ...connectionOutput(found),
            next: 'Use this connection, or add --new to ask for another.' }, args);
          return 0;
        }
        const request = await requestConnection(client, { owner: connectionOwnerId, method: chosen.method, why: args.values.why,
          name: args.values.name, appId: args.values.app, connectionId: args.values.connection,
          scopes: args.values.scopes === undefined ? undefined : z.array(z.string()).parse(await json(args.values.scopes, [])) });
        await output({ kind: 'requested', requestId: request.id, executionId: request.executionId, to: request.to,
          method: chosen.method.id, outputs: connectionMethod(chosen.method).outputs, url: await linked(request.url, client.identity),
          expiresAt: request.expiresAt,
          next: 'Give the URL to ' + (request.to?.name ?? 'the owner') + ', then run foundation connect wait-request ' + request.id }, args);
        if (!args.values.wait) return 0;
        const result = await awaitRequestedConnection(client, request, seconds(args.values.timeout, 1800));
        await output(result, { ...args, values: { ...args.values, force: true } });
        return result.kind === 'connected' ? 0 : 1;
      }
    }
    let progress: FlowProgress | Awaited<ReturnType<typeof startConnection>>;
    if (action === 'start') progress = await startConnection(client, { ownerId: owner,
      methodId: requireArgument(args.values.method, 'Choose --method ID, or name a service.'), name: args.values.name,
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
      ...(args.values.confirmation ? { confirmation: Id.parse(args.values.confirmation) } : {}),
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
  if (command === 'transfer') {
    const id = Id.parse(requireArgument(args.positionals[0], 'Supply the resource ID.'));
    const to = Id.parse(requireArgument(args.values.to, 'Choose the receiving principal with --to ID.'));
    const result = await transferResource(client, id, to, () => privateClient(client).custody);
    if ('url' in result) process.stderr.write('The current owner keeps the item until the recipient accepts. Send this link to the recipient: ' + result.url + '\n');
    await output(result, args);
    return 0;
  }
  if (command === 'ssh-key') {
    const result = await sshKeyCommand(client, args, owner, commandArguments);
    if (typeof result === 'number') return result;
    await output(result, args);
    return 0;
  }
  if (command === 'ssh-host') {
    await output(await sshHostCommand(client, args, owner), args);
    return 0;
  }
  if (command === 'ssh-access') {
    const result = await sshAccessCommand(client, args);
    await output(result, args);
    return 'accounts' in (result as object) && (result as { accounts: Array<{ outcome: string }> }).accounts
      .some(account => account.outcome !== 'verified') ? 1 : 0;
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
                input: { subjectId: current.principal.id, relation: 'delegate', objectId: '$approver' },
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
    error instanceof IdentityVerificationRequired
      ? error.recipient.name + ' (' + error.recipient.id + '): ' +
        (error.code === 'identity_changed' ? 'the previously verified public keys changed.' : 'the public keys have not been verified.') +
        '\nVerify the fingerprint with this principal, then run foundation trust ' + error.recipient.id +
        ' --fingerprint <verified-fingerprint> and repeat this operation.'
      : error instanceof ApiError
      ? error.code + ': ' + error.message + (error.details === undefined ? '' : '\n' + JSON.stringify(error.details))
      : error instanceof z.ZodError
        ? 'Check the command inputs against foundation schema.'
        : error instanceof Error
          ? error.message
          : 'The command failed.';
  process.stderr.write('foundation: ' + message + '\n');
  process.exitCode = 1;
}
