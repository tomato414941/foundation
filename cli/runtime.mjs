#!/usr/bin/env node
import { open, mkdir, stat, mkdtemp, writeFile, chmod, readFile, rename } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { rmSync, constants } from 'node:fs';
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
//   exec     hand what is kept to a command without it passing through the agent. If the agent fetched the
//            values itself they would be in its context, which is the one thing this is here to prevent.
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

async function main() {
  const [action, ...args] = process.argv.slice(2);
  const agentName = (process.env.FOUNDATION_AGENT || '').trim();
  if (agentName && !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/.test(agentName)) throw new Error('FOUNDATION_AGENT must be 1-40 characters of letters, digits, space, dot, underscore or hyphen.');
  if (action === '--version' || action === 'version') { console.log(VERSION); return; }
  const configured = process.env.FOUNDATION_URL || await savedUrl();
  if (action === '--help' || action === 'help' || action === 'guide' || !action) {
    let adapters;
    if (configured) {
      try {
        const response = await fetch(new URL('/v1/adapters', configured), { redirect: 'error', signal: AbortSignal.timeout(5_000) });
        const catalog = await response.json();
        if (response.ok && Array.isArray(catalog.adapters)) adapters = catalog.adapters;
      } catch {}
    }
    console.log(guide(adapters));
    return;
  }
  const separatorAt = args.indexOf('--'), command = separatorAt >= 0 ? args.slice(separatorAt + 1) : [];
  // Each thing to hand over is a path, optionally under the name the command expects it as:
  //   exec aws/access-key-id -- …                     the name comes from the path
  //   exec GH_TOKEN=github/token -- …                  the command decides what to call it
  //   exec KEY_PATH=apple/key:AuthKey.p8 -- …          it arrives as a file, and the name holds its path
  const paths = action === 'exec' && separatorAt > 0 ? args.slice(0, separatorAt).map(value => {
    const at = value.indexOf('='), named = at > 0 ? value.slice(at + 1) : value;
    const colon = named.lastIndexOf(':');
    const path = colon > 0 ? named.slice(0, colon) : named, filename = colon > 0 ? named.slice(colon + 1) : undefined;
    return { path, ...(at > 0 ? { as: value.slice(0, at) } : {}), ...(filename ? { filename } : {}) };
  }) : [];
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
  } else if (!(action === 'exec' && paths.length && new Set(paths.map(item => (item.as ?? '') + ':' + item.path)).size === paths.length && command.length)) {
    throw new Error('Usage: connect [<url>] [--name <name>] | exec [<NAME>=]<path> [...] -- <command> [args...] | api <method> </path> [--json <body>] [--from <file>]');
  }
  const url = serverUrl(connectTo ?? configured);
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const token = await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  async function send(target, payload, accept) {
    const response = await fetch(url.origin + target, { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify(payload), redirect: 'error', signal: AbortSignal.timeout(30_000) });
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
    const answer = await send('/v1/access-requests', { name: name ?? hostname() + ' の ' + (agentName || 'AI') }, data => data.error?.code === 'already_approved');
    if (connectTo !== undefined) await saveUrl(url.origin);
    console.log(answer.error ? 'Already approved on ' + url.origin + '.' : JSON.stringify(answer, null, 2));
    console.log('\nKey file: ' + keyPath + '\nServer: ' + url.origin + (connectTo !== undefined ? ' (saved to ' + configPath() + ')' : '') + '\nEverything else is HTTP: Authorization: Bearer <the contents of that file>');
    return;
  }
  const { delivery } = await send('/v1/deliver', { paths });
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
  for (const file of delivery.files) {
    if (typeof file.env !== 'string' || typeof file.filename !== 'string' || typeof file.content !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(file.filename) || file.filename.startsWith('.')) throw new Error('Foundation described an invalid file.');
  }
  environment.FOUNDATION_PATHS = paths.map(item => item.path).join(',');
  // Files exist in a private directory for exactly as long as the command runs.
  let secretDir;
  if (delivery.files.length) {
    secretDir = await mkdtemp(join(process.env.XDG_RUNTIME_DIR && (await stat(process.env.XDG_RUNTIME_DIR).catch(() => null))?.isDirectory() ? process.env.XDG_RUNTIME_DIR : tmpdir(), 'foundation-'));
    await chmod(secretDir, 0o700);
    for (const file of delivery.files) {
      const target = join(secretDir, file.filename);
      await writeFile(target, file.encoding === 'base64' ? Buffer.from(file.content, 'base64') : file.content, { mode: 0o600, flag: 'wx' });
      assign(file.env, target);
    }
  }
  const cleanup = () => { if (secretDir) rmSync(secretDir, { recursive: true, force: true }); };
  process.once('exit', cleanup);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.once(signal, () => { cleanup(); process.exit(1); });
  try {
    const child = spawn(command[0], command.slice(1), { stdio: 'inherit', env: environment, shell: false });
    process.exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (value, signal) => resolve(value ?? (signal ? 1 : 0))); });
  } finally { cleanup(); }
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check the Foundation URL and network access.' : error.message); process.exitCode = 1; });
