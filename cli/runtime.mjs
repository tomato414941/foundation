#!/usr/bin/env node
import { open, mkdir, stat, lstat, mkdtemp, writeFile, chmod, readFile, rename } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { rmSync, readdirSync, constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { homedir, hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import { validEnvName } from './env-name.mjs';
import { createCredential, answer } from './webauthn.mjs';
import { newContentKey, sealContent, seal, open as openEnvelope, openContent, generateKey } from './envelope.mjs';

// This program does only what the agent running it cannot do for itself.
//
// Everything Foundation offers is plain HTTP, and an agent with the key can call it directly; a command
// wrapper around those calls would only narrow what the agent is allowed to think of. Two things are left:
//   init     say which server, and make this machine's WebAuthn credential: the machine becomes a principal there, of
//            nobody's. Its private key has to exist as a private file before anything can be asked, and nothing prints it.
//   join     ask a person to make this machine their agent, so that it may act for them.
//   token    prove this machine with its credential and print a bearer token that lasts an hour, for calling the API.
//   exec     hand what is kept to a command, or keep a file it creates, without the bytes passing through
//            the agent. If the agent fetched the values itself they would be in its context.
// There is also `api`, which is for people and for scripts rather than for agents: it attaches the key to a
// request and prints what comes back. One escape hatch, so that the API can grow without this program growing
// a verb for every endpoint, and without deciding for an agent how it ought to use any of them.
// The key file: this machine's WebAuthn credential - its id, whose it is, and its private key - kept private, and
// the machine's own key for what is sealed for it (envelope.mjs). Both private halves are made here and never leave;
// Foundation keeps only the public halves. A file may instead hold an access key Foundation issued - as handed out on the
// web for a machine, or given to a lent machine - and, unless it is a lent machine's, it is replaced with a credential the
// first time it is used.
async function readKey(path, { missingOk = false } = {}) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await handle.stat();
    if (!info.isFile() || info.size > 4096 || (info.mode & 0o077) || (process.getuid && info.uid !== process.getuid())) throw new Error('Runtime key file must be owned by the current user and private (mode 600).');
    const content = (await handle.readFile('utf8')).trim();
    if (/^fdn_[A-Za-z0-9_-]{43}$/.test(content)) return { token: content };
    let credential, own;
    try { ({ webauthn_credential: credential, key: own } = JSON.parse(content)); } catch {}
    if (typeof credential?.id !== 'string' || typeof credential.user !== 'string' || credential.private_key?.kty !== 'EC') throw new Error('Invalid runtime key file.');
    if (own !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(own?.private_key ?? '')) throw new Error('Invalid runtime key file.');
    return { credential, own };
  } catch (error) {
    if (error.code === 'ENOENT') { if (missingOk) return null; throw new Error('No key yet. Run: foundation init'); }
    if (error.code === 'ELOOP') throw new Error('Runtime key file must not be a symbolic link.');
    throw error;
  } finally { await handle?.close(); }
}
async function writeKey(path, content, privateDirectory) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  if (privateDirectory) {
    const directory = await stat(dirname(path));
    if ((directory.mode & 0o077) || (process.getuid && directory.uid !== process.getuid())) throw new Error('Foundation key directory must be owned by the current user and private (mode 700).');
  }
  const created = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
  try { await created.writeFile(content + '\n'); await created.sync(); } finally { await created.close(); }
}

const VERSION = createRequire(import.meta.url)('./package.json').version;
// Which server this machine talks to is a setting, not part of the program: `init <url>` writes it here,
// and FOUNDATION_URL, when set, wins for that one run.
const configPath = () => join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'foundation', 'config.json');
async function savedUrl() {
  try { return JSON.parse(await readFile(configPath(), 'utf8')).url || ''; }
  catch (error) { if (error.code === 'ENOENT') return ''; throw new Error('Cannot read ' + configPath() + ': ' + error.message); }
}
async function saveUrl(origin) {
  const path = configPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path + '.tmp', JSON.stringify({ url: origin }, null, 2) + '\n', { mode: 0o600 });
  await rename(path + '.tmp', path);
}
function serverUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('No Foundation server yet. Run: foundation init <url>'); }
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('The Foundation URL must be an HTTPS origin (HTTP is allowed only on localhost).');
  return url;
}

const validFilename = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
async function outputBytes(path) {
  let handle;
  try {
    const directory = await lstat(dirname(path));
    if (!directory.isDirectory() || (directory.mode & 0o077) || (process.getuid && directory.uid !== process.getuid())) throw new Error('Output directory must stay private (mode 700) and owned by the current user.');
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await handle.stat(), limit = 1024 * 1024;
    if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077) || (process.getuid && info.uid !== process.getuid())) throw new Error('Output must be a private regular file owned by the current user (mode 600).');
    if (info.size > limit) throw new Error('Output must contain 1 byte to 1MB.');
    // Bound the read too: the file may grow after stat, or still have a writer.
    const bytes = Buffer.alloc(limit + 1);
    let size = 0;
    while (size < bytes.length) {
      const { bytesRead } = await handle.read(bytes, size, bytes.length - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (!size || size > limit) throw new Error('Output must contain 1 byte to 1MB.');
    return bytes.subarray(0, size);
  } catch (error) {
    if (error.code === 'ELOOP') throw new Error('Output must not be a symbolic link.');
    if (error.code === 'ENOENT') throw new Error('The command did not create its output file.');
    throw error;
  } finally { await handle?.close(); }
}

// --help describes the CLI. The server publishes its API contract at /openapi.json.
const HELP = `Usage: foundation <command> [options]

Commands:
  init [<url>] [--name <name>]         Make this machine's credential: it becomes a principal of its own.
                                       With <url>, remember that Foundation server for later commands.
  join                                 Ask a person to make this machine their agent.
  token                                Print a bearer token for the API, valid for an hour.
  api <METHOD> </path> [--json <body>] [--from <file>] [--type <media-type>]
                                       Send one request to the Foundation API as this machine.
  exec <ENV>=<name> [...] -- <command> [args...]
                                       Run a command with saved values in its environment.
  exec --inputs '<json>' -- <command>  The same, with files, structured inputs, or a connection for a service by id.
  exec --output '<json>' -- <command>  Also save a file the command writes.
  keep <name> --from <file>            Save a file as a secret, sealed here for whoever may open it.
  read <name>                          Print a secret this machine was handed an envelope for.
  version                              Print the version.

API specification:
  foundation api GET /openapi.json      Read the server's OpenAPI specification; no key required.

Environment:
  FOUNDATION_URL               The server for this run (otherwise the one saved by init).
  FOUNDATION_AGENT             Your name, such as claude or codex; gives each agent its own key file.
  FOUNDATION_RUNTIME_KEY_FILE  Where the key file (this machine's credential) is.
`;

async function main() {
  const [action, ...args] = process.argv.slice(2);
  const agentName = (process.env.FOUNDATION_AGENT || '').trim();
  if (agentName && !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/.test(agentName)) throw new Error('FOUNDATION_AGENT must be 1-40 characters of letters, digits, space, dot, underscore or hyphen.');
  if (action === '--version' || action === '-v' || action === 'version') { console.log(VERSION); return; }
  const configured = process.env.FOUNDATION_URL || await savedUrl();
  if (action === '--help' || action === '-h' || action === 'help' || !action) { console.log(HELP); return; }
  const separatorAt = args.indexOf('--'), command = separatorAt >= 0 ? args.slice(separatorAt + 1) : [];
  // Names remain literal. Inputs inject bytes; an optional output saves one generated file.
  let names = [], output;
  if (action === 'exec' && separatorAt > 0) {
    const parsed = parseArgs({ args: args.slice(0, separatorAt), options: { inputs: { type: 'string' }, output: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.values.inputs !== undefined && parsed.positionals.length) throw new Error('--inputs and ENV=name are alternatives.');
    if (parsed.values.inputs !== undefined) {
      try { names = JSON.parse(parsed.values.inputs); } catch { throw new Error('--inputs must be a JSON array of {name, as, filename?} or {id, output?, as?, filename?}.'); }
    } else names = parsed.positionals.map(value => {
      const at = value.indexOf('=');
      if (at < 1) throw new Error('Specify the environment variable explicitly: ENV=name');
      return { name: value.slice(at + 1), as: value.slice(0, at) };
    });
    // A connection for a service names its own variables, so an input may leave `as` out; a secret must say where it goes.
    if (!Array.isArray(names) || names.length > 16 || names.some(item => {
      if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).some(key => !['name', 'id', 'output', 'as', 'filename'].includes(key))) return true;
      if (Object.hasOwn(item, 'name') === Object.hasOwn(item, 'id')) return true;
      if (Object.hasOwn(item, 'name') && (typeof item.name !== 'string' || !item.name || Object.hasOwn(item, 'output'))) return true;
      if (Object.hasOwn(item, 'id') && (typeof item.id !== 'string' || !/^[0-9a-f-]{36}$/.test(item.id))) return true;
      if (Object.hasOwn(item, 'output') && (typeof item.output !== 'string' || !item.output || item.output.length > 200)) return true;
      return item.as !== undefined && item.as !== null && !validEnvName(item.as);
    })) throw new Error('Each input needs exactly one of name or id. Use output with a connection id; as must be a non-reserved environment variable.');
    const chosen = names.map(item => item.as).filter(value => typeof value === 'string');
    if (new Set(chosen).size !== chosen.length) throw new Error('Each input needs a different environment variable.');
    if (parsed.values.output !== undefined) {
      try { output = JSON.parse(parsed.values.output); } catch { throw new Error('--output must be a JSON object {name, as, filename}.'); }
      if (!output || Array.isArray(output) || typeof output !== 'object' || Object.keys(output).some(key => !['name', 'as', 'filename'].includes(key))) throw new Error('--output must be a JSON object {name, as, filename}.');
      if (typeof output.name !== 'string' || !output.name.length || output.name.length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(output.name) || !output.name.isWellFormed()) throw new Error('Output name must be 1-200 characters without control characters.');
      if (!validEnvName(output.as) || !validFilename(output.filename)) throw new Error('Output needs a non-reserved environment variable in as and a filename starting with a letter or digit (up to 64 letters, digits, dots, underscores or hyphens).');
      if (names.some(item => item.as === output.as)) throw new Error('Output needs a different environment variable from every input.');
    }
  }
  let call, serverGiven, name;
  if (action === 'init') {
    const parsed = parseArgs({ args, options: { name: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length > 1) throw new Error('Usage: init [<url>] [--name <name>]');
    serverGiven = parsed.positionals[0];
    name = parsed.values.name;
  } else if (action === 'join') {
    if (args.length) throw new Error('Usage: join');
  } else if (action === 'api') {
    const parsed = parseArgs({ args, options: { json: { type: 'string' }, from: { type: 'string' }, type: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 2 || !/^(GET|POST|PUT|DELETE|PATCH)$/.test(parsed.positionals[0]) || !parsed.positionals[1].startsWith('/')) {
      throw new Error('Usage: api <GET|POST|PUT|DELETE|PATCH> </path> [--json <body>] [--from <file>] [--type <media-type>]');
    }
    if (parsed.values.json !== undefined && parsed.values.from !== undefined) throw new Error('--json and --from are alternatives.');
    // A request that carries nothing still says so in JSON, which is what the server asks of anything but a GET.
    const method = parsed.positionals[0];
    const content = parsed.values.from !== undefined ? await readFile(parsed.values.from) : parsed.values.json !== undefined ? Buffer.from(parsed.values.json) : method === 'GET' ? undefined : Buffer.from('{}');
    call = { method, target: parsed.positionals[1], body: content,
      type: parsed.values.type || (parsed.values.from !== undefined ? 'application/octet-stream' : 'application/json') };
  } else if (action === 'keep') {
    const parsed = parseArgs({ args, options: { from: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1 || parsed.values.from === undefined) throw new Error('Usage: keep <name> --from <file>');
    const content = await readFile(parsed.values.from);
    if (!content.length || content.length > 1024 * 1024) throw new Error('A secret must contain 1 byte to 1MB.');
    call = { name: parsed.positionals[0], body: content };
  } else if (action === 'read') {
    if (args.length !== 1) throw new Error('Usage: read <name>');
    call = { name: args[0] };
  } else if (action === 'token') {
    if (args.length) throw new Error('Usage: token');
  } else if (!(action === 'exec' && (names.length || output) && command.length)) {
    throw new Error('Usage: init [<url>] [--name <name>] | join | token | exec [<ENV>=<name> ... | --inputs <json>] [--output <json>] -- <command> [args...] | keep <name> --from <file> | read <name> | api <method> </path> [--json <body>] [--from <file>]');
  }
  const url = serverUrl(serverGiven ?? configured);
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const publicSpec = action === 'api' && call.method === 'GET' && call.target === '/openapi.json';
  let key = publicSpec ? null : await readKey(keyPath, { missingOk: action === 'init' }), token = key?.token ?? null;
  // The credential proves this machine for an hour at a time: the challenge is answered for the server actually reached.
  async function prove() {
    const begin = await fetch(url.origin + '/v1/session', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'webauthn' }), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const { options } = await begin.json();
    const response = await fetch(url.origin + '/v1/session', { method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ kind: 'webauthn', credential: answer(options, key.credential, url.origin), session: 'token' }), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const proven = await response.json();
    if (!response.ok || typeof proven.token !== 'string') throw new Error('Foundation did not accept this machine\'s credential (' + response.status + ', ' + (proven.error?.code || 'unknown') + ').');
    return proven.token;
  }
  async function send(target, payload, { accept, method = 'POST', type = 'application/json' } = {}) {
    const response = await fetch(url.origin + target, { method, headers: { authorization: 'Bearer ' + token, ...(payload === undefined ? {} : { 'content-type': type }) },
      body: payload === undefined ? undefined : type === 'application/json' ? JSON.stringify(payload) : payload, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const data = await response.json();
    if (!response.ok && !accept?.(data)) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
    return data;
  }
  // A key file holding an issued access key: register a WebAuthn credential with it, and keep the credential instead.
  // A lent machine's key stays as it is; it ends with the machine.
  async function upgrade(label) {
    const me = await send('/v1/principals/me', undefined, { method: 'GET' });
    if (me.key?.environment) return;
    const { options } = await send('/v1/principals/' + encodeURIComponent(me.principal.id) + '/credentials', { kind: 'webauthn' });
    const made = createCredential(options, url.origin);
    await send('/v1/principals/' + encodeURIComponent(me.principal.id) + '/credentials', { kind: 'webauthn', name: label, credential: made.response }, { method: 'PUT' });
    await writeKey(keyPath, JSON.stringify({ webauthn_credential: made.credential }), !process.env.FOUNDATION_RUNTIME_KEY_FILE);
    key = { credential: made.credential };
  }
  // This machine's own key, made and published once it is a principal here: what is sealed for it opens with this.
  // A key published elsewhere for this principal stays as it is; then nothing sealed for it opens here.
  async function publishKey() {
    if (key.own) return;
    const made = generateKey();
    const published = await send('/v1/principals/me/key', { public_key: made.publicKey.toString('base64url') }, { method: 'PUT', accept: data => data.error?.code === 'key_exists' });
    if (published.error) return;
    key.own = { private_key: made.privateKey.toString('base64url') };
    await writeKey(keyPath, JSON.stringify({ webauthn_credential: key.credential, key: key.own }), !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  }
  if (key?.token && action !== 'init') { await upgrade(hostname() + ' の ' + (agentName || 'AI')); }
  // A credential this server no longer knows leaves initialising again; anything else needs it.
  if (key?.credential) {
    try { token = await prove(); await publishKey(); }
    catch (error) { if (action !== 'init') throw error; key = null; token = null; }
  }
  if (action === 'token') { console.log(token); return; }
  // One request, as this machine, and the answer printed as it came. Nothing here knows the endpoints.
  if (action === 'api') {
    if (!publicSpec && !/[?&]as=/.test(call.target)) {
      const me = await send('/v1/principals/me', undefined, { method: 'GET', accept: () => true });
      if (me.acts_for?.length === 1) call.target += (call.target.includes('?') ? '&' : '?') + 'as=' + encodeURIComponent(me.acts_for[0]);
    }
    const response = await fetch(url.origin + call.target, { method: call.method, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), ...(call.body === undefined ? {} : { 'content-type': call.type }) },
      ...(call.body === undefined ? {} : { body: call.body }), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const bytes = Buffer.from(await response.arrayBuffer());
    process.stdout.write(bytes);
    if (bytes.length && !bytes.subarray(-1).equals(Buffer.from('\n'))) process.stdout.write('\n');
    if (!response.ok) process.exitCode = 1;
    return;
  }
  // Becoming a principal here: a key this server knows has nothing to make; initialising again only changes which
  // server is remembered. The key itself is never printed: it stays in the file.
  if (action === 'init') {
    const wanted = name ?? hostname() + ' の ' + (agentName || 'AI');
    let me = null;
    if (token) me = await send('/v1/principals/me', undefined, { method: 'GET', accept: data => data.error?.code === 'not_approved' });
    if (!token || me?.error) {
      // No key, or one this server does not know: a WebAuthn credential made here, proven by nobody, makes this machine a
      // principal there, of nobody's - the same call a browser's passkey makes.
      key = null; me = null;
      const post = (method, payload) => fetch(url.origin + '/v1/principals', { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), redirect: 'error', signal: AbortSignal.timeout(30_000) });
      const begun = await post('POST', { kind: 'webauthn', name: wanted });
      const { options, error } = await begun.json();
      if (!begun.ok) throw new Error('Foundation did not begin a credential (' + begun.status + ', ' + (error?.code || 'unknown') + ').');
      const made = createCredential(options, url.origin);
      const done = await post('PUT', { kind: 'webauthn', name: wanted, principal_name: wanted, credential: made.response, session: 'token' });
      const became = await done.json();
      if (!done.ok || typeof became.token !== 'string') throw new Error('Foundation did not accept this machine\'s credential (' + done.status + ', ' + (became.error?.code || 'unknown') + ').');
      key = { credential: made.credential }; token = became.token;
      await writeKey(keyPath, JSON.stringify({ webauthn_credential: key.credential }), !process.env.FOUNDATION_RUNTIME_KEY_FILE);
      await publishKey();
    } else if (key?.token) { await upgrade(wanted); token = await prove(); await publishKey(); }
    if (serverGiven !== undefined) await saveUrl(url.origin);
    if (!me) me = await send('/v1/principals/me', undefined, { method: 'GET' });
    console.log(JSON.stringify({ principal: me.principal, acts_for: me.acts_for ?? [] }, null, 2));
    console.log('\nKey file: ' + keyPath + '\nServer: ' + url.origin + (serverGiven !== undefined ? ' (saved to ' + configPath() + ')' : '') + '\nTo act for someone: foundation join\nEverything else is HTTP: Authorization: Bearer $(foundation token)');
    return;
  }
  // Asking a person to make this machine their agent. One they already approved has nothing to ask.
  if (action === 'join') {
    const me = await send('/v1/principals/me', undefined, { method: 'GET', accept: data => data.error?.code === 'not_approved' });
    if (me.acts_for?.length) { console.log('Already approved on ' + url.origin + '.'); return; }
    const answer = await send('/v1/requests', { authorization_details: [{ type: 'relation', relation: 'agent' }] });
    console.log(JSON.stringify(answer, null, 2));
    return;
  }
  // Reading a secret this machine was handed an envelope for: its own, or one shown to it along a line.
  if (action === 'read') {
    if (!key.own) throw new Error('This machine has no key of its own here, so nothing sealed for it can be opened.');
    const own = await send('/v1/principals/me/resources?kind=secret&name=' + encodeURIComponent(call.name), undefined, { method: 'GET', accept: () => true });
    const resource = own.resource ?? (await send('/v1/principals/me/resources?shown=me', undefined, { method: 'GET' })).resources.find(item => item.kind === 'secret' && item.name === call.name);
    if (!resource) throw new Error('No secret named ' + JSON.stringify(call.name) + ' is kept by this machine or shown to it.');
    const kept = await send('/v1/resources/' + resource.id + '/content', undefined, { method: 'GET' });
    if (!kept.envelope) throw new Error('No envelope was made for this machine: it may read about this secret, but was not handed its key.');
    const contentKey = openEnvelope(Buffer.from(kept.envelope, 'base64url'), Buffer.from(key.own.private_key, 'base64url'));
    process.stdout.write(openContent(contentKey, Buffer.from(kept.content, 'base64url')));
    return;
  }
  // Nothing runs before someone has accepted this key: a key that acts for nobody reaches only its own empty resources,
  // and the person it asked has yet to answer.
  const current = await send('/v1/principals/me', undefined, { method: 'GET' });
  // A key given to a lent machine acts as its principal's own self. Any other key acts for someone once approved;
  // until then, whether waiting or refused, it has nothing to run with.
  const own = Boolean(current.key?.environment);
  if (!own && !current.acts_for?.length) throw new Error('Foundation request failed (401, not_approved). This key acts for nobody yet' + (current.requests?.[0] ? '; it is waiting for approval at ' + current.requests[0].verification_uri : '') + '.');
  // Whose resources a run reaches: the one this key acts for, the one named when it acts for several, or its own.
  const acting = current.acts_for ?? [];
  const owner = process.env.FOUNDATION_AS || (acting.length === 1 ? acting[0] : null);
  if (!owner && acting.length > 1) throw new Error('This key acts for several principals. Set FOUNDATION_AS=<principal id> to say which one this run is for.');
  const forHolder = target => owner ? target + (target.includes('?') ? '&' : '?') + 'as=' + encodeURIComponent(owner) : target;
  // A secret is sealed here, with a key of its own, for each of the owner's recipients: the server keeps what it
  // cannot open. This machine is not among them; it places the bytes and does not read them back.
  const sealedFor = async bytes => {
    const { recipients } = await send('/v1/principals/' + encodeURIComponent(owner || 'me') + '/recipients', undefined, { method: 'GET' });
    if (!Array.isArray(recipients) || !recipients.length) throw new Error('Nobody can open a secret kept for this owner yet: the owner needs a key, or Foundation needs to act for them.');
    const contentKey = newContentKey();
    return { content: sealContent(contentKey, bytes).toString('base64url'), envelopes: Object.fromEntries(recipients.map(item => [item.principal_id, seal(contentKey, Buffer.from(item.public_key, 'base64url')).toString('base64url')])) };
  };
  if (action === 'keep') {
    const saved = await send('/v1/principals/' + encodeURIComponent(owner || 'me') + '/resources?kind=secret&name=' + encodeURIComponent(call.name), await sealedFor(call.body), { method: 'PUT' });
    try { await send('/v1/principals/me/relations', { relation: 'editor', object_type: 'resource', object_id: saved.resource.id }, { method: 'DELETE' }); } catch {}
    console.log(JSON.stringify(saved));
    return;
  }
  // A secret this machine was handed an envelope for is opened here, with its own key: the server keeps what it cannot
  // open, and nobody else has to be able to open it for this machine to use it. Everything else - a connection, a secret
  // not handed to this machine - is asked of the server, which hands over only what Foundation may open for the owner.
  const handed = { environment: {}, files: [] };
  let asked = names;
  if (key.own && names.some(item => typeof item.name === 'string')) {
    const shown = owner ? (await send('/v1/principals/me/resources?shown=me', undefined, { method: 'GET', accept: () => true })).resources ?? [] : [];
    asked = [];
    for (const item of names) {
      let resource = null;
      if (typeof item.name === 'string') {
        resource = owner ? shown.find(row => row.kind === 'secret' && row.name === item.name && row.owner_id === owner)
          : (await send('/v1/principals/me/resources?kind=secret&name=' + encodeURIComponent(item.name), undefined, { method: 'GET', accept: () => true })).resource;
      }
      const kept = resource ? await send('/v1/resources/' + resource.id + '/content', undefined, { method: 'GET', accept: () => true }) : null;
      if (!kept?.envelope) { asked.push(item); continue; }
      const bytes = openContent(openEnvelope(Buffer.from(kept.envelope, 'base64url'), Buffer.from(key.own.private_key, 'base64url')), Buffer.from(kept.content, 'base64url'));
      if (item.filename !== undefined) handed.files.push({ env: item.as, filename: item.filename, content: bytes.toString('base64'), encoding: 'base64' });
      else handed.environment[item.as] = bytes.toString('utf8');
    }
  }
  let injection;
  if (asked.length) ({ injection } = await send(forHolder('/v1/injections'), { names: asked }));
  else injection = { environment: {}, files: [] };
  if (!injection || typeof injection.environment !== 'object' || !Array.isArray(injection.files)) throw new Error('Foundation returned an invalid injection.');
  injection = { environment: { ...injection.environment, ...handed.environment }, files: [...injection.files, ...handed.files] };
  // What each of them sets is the server's to say; this applies it and refuses anything it may not set.
  const environment = { ...process.env };
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const assign = (name, value) => {
    if (!validEnvName(name)) throw new Error('Foundation named a reserved environment variable (' + name + ').');
    if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || value.length > 16384) throw new Error('Foundation returned an invalid value for ' + name + '.');
    environment[name] = value;
  };
  for (const [name, value] of Object.entries(injection.environment)) assign(name, value);
  const fileNames = new Set(), variables = new Set(Object.keys(injection.environment));
  for (const file of injection.files) {
    if (typeof file.env !== 'string' || typeof file.content !== 'string' || !validFilename(file.filename) || !validEnvName(file.env) || fileNames.has(file.filename) || variables.has(file.env)) throw new Error('Foundation described an invalid file.');
    fileNames.add(file.filename); variables.add(file.env);
  }
  if (output && variables.has(output.as)) throw new Error('Output needs a different environment variable from every input.');
  environment.FOUNDATION_NAMES = JSON.stringify(names.map(item => item.name ?? item.id));
  // Injected inputs are always cleaned up. A completed output survives only an unconfirmed upload.
  let secretDir, outputDir, outputPath, child, interrupted = false, retainOutput = false;
  const cleanup = () => {
    if (secretDir) rmSync(secretDir, { recursive: true, force: true });
    if (outputDir) {
      if (!retainOutput) rmSync(outputDir, { recursive: true, force: true });
      else for (const entry of readdirSync(outputDir)) {
        if (entry !== output.filename) rmSync(join(outputDir, entry), { recursive: true, force: true });
      }
    }
  };
  const recovery = () => 'Foundation could not confirm the output was saved. The private output file is retained for recovery: ' + outputPath + '\nRetry with foundation keep <name> --from <file>, then remove that recovery file.';
  process.once('exit', cleanup);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.once(signal, () => {
    interrupted = true;
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      child.kill(signal);
      setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
      return;
    }
    if (retainOutput) console.error(recovery());
    cleanup(); process.exit(1);
  });
  try {
    const temporaryDirectory = async () => {
      const directory = await mkdtemp(join(process.env.XDG_RUNTIME_DIR && (await stat(process.env.XDG_RUNTIME_DIR).catch(() => null))?.isDirectory() ? process.env.XDG_RUNTIME_DIR : tmpdir(), 'foundation-'));
      await chmod(directory, 0o700);
      return directory;
    };
    if (injection.files.length) {
      secretDir = await temporaryDirectory();
      for (const file of injection.files) {
        const target = join(secretDir, file.filename);
        await writeFile(target, file.encoding === 'base64' ? Buffer.from(file.content, 'base64') : file.content, { mode: 0o600, flag: 'wx' });
        assign(file.env, target);
      }
    }
    if (output) {
      outputDir = await temporaryDirectory();
      outputPath = join(outputDir, output.filename);
      await writeFile(outputPath, '', { mode: 0o600, flag: 'wx' });
      assign(output.as, outputPath);
    }
    child = spawn(command[0], command.slice(1), { stdio: 'inherit', env: environment, shell: false });
    process.exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (value, signal) => resolve(interrupted ? 1 : value ?? (signal ? 1 : 0))); });
    if (output && process.exitCode === 0) {
      const bytes = await outputBytes(outputPath);
      retainOutput = true;
      // The command wrote it; the agent never saw it, and keeps it that way: the line drawn for the one who kept it is declined.
      let saved;
      try { saved = await send('/v1/principals/' + encodeURIComponent(owner || 'me') + '/resources?kind=secret&name=' + encodeURIComponent(output.name), await sealedFor(bytes), { method: 'PUT' }); }
      catch { throw new Error(recovery()); }
      try { await send('/v1/principals/me/relations', { relation: 'editor', object_type: 'resource', object_id: saved.resource.id }, { method: 'DELETE' }); } catch {}
      retainOutput = false;
      console.error('Saved output as ' + JSON.stringify(output.name) + '.');
    }
  } finally { cleanup(); }
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check the Foundation URL and network access.' : error.message); process.exitCode = 1; });
