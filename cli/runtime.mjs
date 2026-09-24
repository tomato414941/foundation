#!/usr/bin/env node
import { open, mkdir, stat, lstat, mkdtemp, writeFile, chmod, readFile, rename } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { rmSync, readdirSync, constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { homedir, hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import { validEnvName } from './env-name.mjs';
import { guide } from './guide.mjs';

// This program does only what the agent running it cannot do for itself.
//
// Everything Foundation offers is plain HTTP, and an agent with the key can call it directly; a command
// wrapper around those calls would only narrow what the agent is allowed to think of. Two things are left:
//   connect  say which server, and make the key. It has to exist as a private file before anything can be asked, and whoever
//            makes it must not print it.
//   exec     hand what is kept to a command, or keep a file it creates, without the bytes passing through
//            the agent. If the agent fetched the values itself they would be in its context.
// There is also `api`, which is for people and for scripts rather than for agents: it attaches the key to a
// request and prints what comes back. One escape hatch, so that the API can grow without this program growing
// a verb for every endpoint, and without deciding for an agent how it ought to use any of them.
async function runtimeKey(path, create, privateDirectory) {
  if (create) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    if (privateDirectory) {
      const directory = await stat(dirname(path));
      if ((directory.mode & 0o077) || (process.getuid && directory.uid !== process.getuid())) throw new Error('Foundation key directory must be owned by the current user and private (mode 700).');
    }
    let created;
    try {
      created = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await created.writeFile('fdn_' + randomBytes(32).toString('base64url') + '\n');
      await created.sync();
    } catch (error) { if (error.code !== 'EEXIST') throw error; }
    finally { await created?.close(); }
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await handle.stat();
    if (!info.isFile() || info.size > 512 || (info.mode & 0o077) || (process.getuid && info.uid !== process.getuid())) throw new Error('Runtime key file must be owned by the current user and private (mode 600).');
    const token = (await handle.readFile('utf8')).trim();
    if (!/^fdn_[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Invalid runtime key file.');
    return token;
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('No key yet. Run: foundation connect');
    if (error.code === 'ELOOP') throw new Error('Runtime key file must not be a symbolic link.');
    throw error;
  } finally { await handle?.close(); }
}

const VERSION = createRequire(import.meta.url)('./package.json').version;
// Which server this machine talks to is a setting, not part of the program: `connect <url>` writes it here,
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
  try { url = new URL(value); } catch { throw new Error('No Foundation server yet. Run: foundation connect <url>'); }
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

// --help is the usual thing: the commands and their options. The guide (what Foundation is and how to ask it
// for things) is its own command, since it is the server's document, not this program's.
const HELP = `Usage: foundation <command> [options]

Commands:
  connect [<url>] [--name <name>]      Make this machine's key and ask the owner to approve it.
                                       With <url>, remember that Foundation server for later commands.
  api <METHOD> </path> [--json <body>] [--from <file>] [--type <media-type>]
                                       Send one request to the Foundation API with the key attached.
  exec <ENV>=<name> [...] -- <command> [args...]
                                       Run a command with saved values in its environment.
  exec --inputs '<json>' -- <command>  The same, with files or structured inputs.
  exec --output '<json>' -- <command>  Also save a file the command writes.
  guide                                The API guide: what Foundation keeps, and how to ask it for things.
  version                              Print the version.

Environment:
  FOUNDATION_URL               The server for this run (otherwise the one saved by connect).
  FOUNDATION_AGENT             Your name, such as claude or codex; gives each agent its own key file.
  FOUNDATION_RUNTIME_KEY_FILE  Where the key file is.
`;

async function main() {
  const [action, ...args] = process.argv.slice(2);
  const agentName = (process.env.FOUNDATION_AGENT || '').trim();
  if (agentName && !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/.test(agentName)) throw new Error('FOUNDATION_AGENT must be 1-40 characters of letters, digits, space, dot, underscore or hyphen.');
  if (action === '--version' || action === '-v' || action === 'version') { console.log(VERSION); return; }
  const configured = process.env.FOUNDATION_URL || await savedUrl();
  if (action === '--help' || action === '-h' || action === 'help' || !action) { console.log(HELP); return; }
  if (action === 'guide') {
    let adapters;
    if (configured) {
      try {
        const response = await fetch(new URL('/v1/connectors', configured), { redirect: 'error', signal: AbortSignal.timeout(5_000) });
        const catalog = await response.json();
        if (response.ok && Array.isArray(catalog.connectors)) adapters = catalog.connectors;
      } catch {}
    }
    console.log(guide(adapters));
    return;
  }
  const separatorAt = args.indexOf('--'), command = separatorAt >= 0 ? args.slice(separatorAt + 1) : [];
  // Names remain literal. Inputs deliver bytes; an optional output saves one generated file.
  let names = [], output;
  if (action === 'exec' && separatorAt > 0) {
    const parsed = parseArgs({ args: args.slice(0, separatorAt), options: { inputs: { type: 'string' }, output: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.values.inputs !== undefined && parsed.positionals.length) throw new Error('--inputs and ENV=name are alternatives.');
    if (parsed.values.inputs !== undefined) {
      try { names = JSON.parse(parsed.values.inputs); } catch { throw new Error('--inputs must be a JSON array of {name, as, filename?}.'); }
    } else names = parsed.positionals.map(value => {
      const at = value.indexOf('=');
      if (at < 1) throw new Error('Specify the environment variable explicitly: ENV=name');
      return { name: value.slice(at + 1), as: value.slice(0, at) };
    });
    if (!Array.isArray(names) || names.length > 16 || names.some(item => !item || typeof item.name !== 'string' || !item.name || !validEnvName(item.as))) throw new Error('Each input needs a name and a non-reserved environment variable in as.');
    if (new Set(names.map(item => item.as)).size !== names.length) throw new Error('Each input needs a different environment variable.');
    if (parsed.values.output !== undefined) {
      try { output = JSON.parse(parsed.values.output); } catch { throw new Error('--output must be a JSON object {name, as, filename}.'); }
      if (!output || Array.isArray(output) || typeof output !== 'object' || Object.keys(output).some(key => !['name', 'as', 'filename'].includes(key))) throw new Error('--output must be a JSON object {name, as, filename}.');
      if (typeof output.name !== 'string' || !output.name.length || output.name.length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(output.name) || !output.name.isWellFormed()) throw new Error('Output name must be 1-200 characters without control characters.');
      if (!validEnvName(output.as) || !validFilename(output.filename)) throw new Error('Output needs a non-reserved environment variable in as and a filename starting with a letter or digit (up to 64 letters, digits, dots, underscores or hyphens).');
      if (names.some(item => item.as === output.as)) throw new Error('Output needs a different environment variable from every input.');
    }
  }
  let call, connectTo, name;
  if (action === 'connect') {
    const parsed = parseArgs({ args, options: { name: { type: 'string' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length > 1) throw new Error('Usage: connect [<url>] [--name <name>]');
    connectTo = parsed.positionals[0];
    name = parsed.values.name;
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
  } else if (!(action === 'exec' && (names.length || output) && command.length)) {
    throw new Error('Usage: connect [<url>] [--name <name>] | exec [<ENV>=<name> ... | --inputs <json>] [--output <json>] -- <command> [args...] | api <method> </path> [--json <body>] [--from <file>]');
  }
  const url = serverUrl(connectTo ?? configured);
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const token = await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  async function send(target, payload, { accept, method = 'POST', type = 'application/json' } = {}) {
    const response = await fetch(url.origin + target, { method, headers: { authorization: 'Bearer ' + token, ...(payload === undefined ? {} : { 'content-type': type }) },
      body: payload === undefined ? undefined : type === 'application/json' ? JSON.stringify(payload) : payload, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const data = await response.json();
    if (!response.ok && !accept?.(data)) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
    return data;
  }
  // One request, with the key attached and the answer printed as it came. Nothing here knows the endpoints.
  if (action === 'api') {
    const response = await fetch(url.origin + call.target, { method: call.method, headers: { authorization: 'Bearer ' + token, ...(call.body === undefined ? {} : { 'content-type': call.type }) },
      ...(call.body === undefined ? {} : { body: call.body }), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const bytes = Buffer.from(await response.arrayBuffer());
    process.stdout.write(bytes);
    if (bytes.length && !bytes.subarray(-1).equals(Buffer.from('\n'))) process.stdout.write('\n');
    if (!response.ok) process.exitCode = 1;
    return;
  }
  // Asking the owner to approve this key. The key itself is never printed: it stays in the file.
  // A key the owner already approved has nothing to ask; connecting again only changes which server is remembered.
  if (action === 'connect') {
    const answer = await send('/v1/keys', { name: name ?? hostname() + ' の ' + (agentName || 'AI') }, { accept: data => data.error?.code === 'already_approved' });
    if (connectTo !== undefined) await saveUrl(url.origin);
    console.log(answer.error ? 'Already approved on ' + url.origin + '.' : JSON.stringify(answer, null, 2));
    console.log('\nKey file: ' + keyPath + '\nServer: ' + url.origin + (connectTo !== undefined ? ' (saved to ' + configPath() + ')' : '') + '\nEverything else is HTTP: Authorization: Bearer <the contents of that file>');
    return;
  }
  // Even output-only commands need an approved key before they start an external login.
  let delivery;
  if (names.length) ({ delivery } = await send('/v1/deliveries', { names }));
  else {
    const current = await send('/v1/keys/current', undefined, { method: 'GET' });
    if (!current.key) throw new Error('Foundation request failed (401, not_approved). This key is waiting for approval at ' + current.request?.verification_uri + '.');
    delivery = { environment: {}, files: [] };
  }
  if (!delivery || typeof delivery.environment !== 'object' || !Array.isArray(delivery.files)) throw new Error('Foundation returned an invalid delivery.');
  // What each of them sets is the server's to say; this applies it and refuses anything it may not set.
  const environment = { ...process.env };
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const assign = (name, value) => {
    if (!validEnvName(name)) throw new Error('Foundation named a reserved environment variable (' + name + ').');
    if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || value.length > 16384) throw new Error('Foundation returned an invalid value for ' + name + '.');
    environment[name] = value;
  };
  for (const [name, value] of Object.entries(delivery.environment)) assign(name, value);
  const fileNames = new Set(), variables = new Set(Object.keys(delivery.environment));
  for (const file of delivery.files) {
    if (typeof file.env !== 'string' || typeof file.content !== 'string' || !validFilename(file.filename) || !validEnvName(file.env) || fileNames.has(file.filename) || variables.has(file.env)) throw new Error('Foundation described an invalid file.');
    fileNames.add(file.filename); variables.add(file.env);
  }
  if (output && variables.has(output.as)) throw new Error('Output needs a different environment variable from every input.');
  environment.FOUNDATION_NAMES = JSON.stringify(names.map(item => item.name));
  // Delivered inputs are always cleaned up. A completed output survives only an unconfirmed upload.
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
  const recovery = () => 'Foundation could not confirm the output was saved. The private output file is retained for recovery: ' + outputPath + '\nRetry with foundation api PUT "/v1/secrets?name=<URL-encoded-name>&secret=true" --from <file>, then remove that recovery file.';
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
    if (delivery.files.length) {
      secretDir = await temporaryDirectory();
      for (const file of delivery.files) {
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
      try { await send('/v1/secrets?name=' + encodeURIComponent(output.name) + '&secret=true', bytes, { method: 'PUT', type: 'application/octet-stream' }); }
      catch { throw new Error(recovery()); }
      retainOutput = false;
      console.error('Saved output as ' + JSON.stringify(output.name) + '.');
    }
  } finally { cleanup(); }
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check the Foundation URL and network access.' : error.message); process.exitCode = 1; });
