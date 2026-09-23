import { open, mkdir, stat, mkdtemp, writeFile, chmod, readFile } from 'node:fs/promises';
import { rmSync } from 'node:fs';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { homedir, hostname, tmpdir } from 'node:os';
import { basename, dirname, extname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { spawnExpoSession } from './expo-runtime.mjs';
import { validEnvName } from './env-name.mjs';
import { guide } from './guide.mjs';

// What a file is served as when --type is not given. Text is served as plain text so a browser shows it.
const TYPES = { '.yaml': 'text/plain; charset=utf-8', '.yml': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8', '.csv': 'text/plain; charset=utf-8', '.log': 'text/plain; charset=utf-8',
  '.json': 'application/json', '.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.zip': 'application/zip' };
const minutesOption = value => { if (value === undefined) return undefined; if (!/^\d{1,5}$/.test(value)) throw new Error('--minutes takes the number of minutes the link stays valid (1-10080).'); return Number(value); };

const readStdin = () => new Promise((resolve, reject) => {
  const chunks = [];
  process.stdin.on('data', chunk => chunks.push(chunk));
  process.stdin.once('end', () => resolve(Buffer.concat(chunks)));
  process.stdin.once('error', reject);
});

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
    if (error.code === 'ENOENT') throw new Error('No Foundation connection yet. Run: node src/runtime.mjs connect');
    if (error.code === 'ELOOP') throw new Error('Runtime key file must not be a symbolic link.');
    throw error;
  } finally { await handle?.close(); }
}

// The access token goes only to the selected child process, never stdout or command arguments.
async function main() {
  const [action, ...args] = process.argv.slice(2);
  const agentName = (process.env.FOUNDATION_AGENT || '').trim();
  if (agentName && !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/.test(agentName)) throw new Error('FOUNDATION_AGENT must be 1-40 characters of letters, digits, space, dot, underscore or hyphen.');
  const separatorAt = args.indexOf('--'), command = separatorAt >= 0 ? args.slice(separatorAt + 1) : [];
  // exec takes what should reach the command: a registered credential by its id, or something kept, by its path.
  const targets = action === 'exec' && separatorAt > 0 ? args.slice(0, separatorAt) : [];
  const credentialIds = targets.filter(target => /^[a-f0-9-]{36}$/.test(target));
  const entryPaths = targets.filter(target => !/^[a-f0-9-]{36}$/.test(target));
  if (action === '--help' || action === 'help' || action === 'guide' || !action) {
    let adapters;
    if (process.env.FOUNDATION_URL) {
      try {
        const response = await fetch(new URL('/v1/adapters', process.env.FOUNDATION_URL), { redirect: 'error', signal: AbortSignal.timeout(5_000) });
        const catalog = await response.json();
        if (response.ok && Array.isArray(catalog.adapters)) adapters = catalog.adapters;
      } catch {}
    }
    console.log(guide(adapters));
    return;
  }
  let options;
  if (action === 'connect') {
    options = parseArgs({ args, options: { adapter: { type: 'string' }, name: { type: 'string', default: hostname() + ' の ' + (agentName || 'AI') }, purpose: { type: 'string', default: '' }, guide: { type: 'string', default: '' }, valid: { type: 'string', default: '' } }, strict: true, allowPositionals: false }).values;
    if (options.guide) { options.guidance = options.guide; } delete options.guide;
    if (options.valid) { if (!/^\d{1,4}$/.test(options.valid)) throw new Error('--valid takes the number of minutes the link stays open (1-1440).'); options.valid_minutes = Number(options.valid); } delete options.valid;
  }
  // Asking the owner to put something into storage: the key says where it goes and how it is handed over,
  // and writes the instructions. Foundation is told nothing about the service.
  else if (action === 'ask') {
    const parsed = parseArgs({ args, options: { env: { type: 'string' }, file: { type: 'string' }, type: { type: 'string' }, label: { type: 'string' }, site: { type: 'string' },
      purpose: { type: 'string', default: '' }, guide: { type: 'string', default: '' }, valid: { type: 'string' }, multiline: { type: 'boolean' }, readable: { type: 'boolean' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1) throw new Error('Usage: ask <path> --label "<what to paste>" [--env NAME] [--file NAME] [--site <https://where it is made>] [--multiline] [--readable] [--purpose "..."] [--guide "..."] [--valid <minutes>]');
    if (!parsed.values.label) throw new Error('--label says what the owner is being asked for; it is required.');
    options = { purpose: parsed.values.purpose, guidance: parsed.values.guide,
      store: { path: parsed.positionals[0], label: parsed.values.label, ...(parsed.values.env ? { env: parsed.values.env } : {}), ...(parsed.values.file ? { filename: parsed.values.file } : {}),
        ...(parsed.values.site ? { site: parsed.values.site } : {}), ...(parsed.values.type ? { type: parsed.values.type } : {}), multiline: parsed.values.multiline === true, secret: parsed.values.readable !== true } };
    if (parsed.values.valid) { if (!/^\d{1,4}$/.test(parsed.values.valid)) throw new Error('--valid takes the number of minutes the link stays open (1-1440).'); options.valid_minutes = Number(parsed.values.valid); }
  }
  else if (action === 'rename') {
    if (args.length !== 1 || !args[0].trim() || args[0].length > 80) throw new Error('Usage: rename <new name> (1-80 characters).');
    options = { name: args[0].trim() };
  }
  // The sharing space: publish a file behind a time-limited URL, or issue that URL again.
  else if (action === 'share' || action === 'link') {
    const parsed = parseArgs({ args, options: { minutes: { type: 'string' }, ...(action === 'share' ? { type: { type: 'string' } } : {}) }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1) throw new Error(action === 'share' ? 'Usage: share <file> [--type <content-type>] [--minutes <n>]' : 'Usage: link <file-id> [--minutes <n>]');
    const minutes = minutesOption(parsed.values.minutes), target = parsed.positionals[0];
    if (action === 'link') options = { id: target, ...(minutes === undefined ? {} : { minutes }) };
    else {
      const info = await stat(target);
      if (!info.isFile() || info.size > 5 * 1024 * 1024) throw new Error('share takes a regular file of at most 5 MB.');
      options = { name: basename(target), type: parsed.values.type || TYPES[extname(target).toLowerCase()] || 'application/octet-stream', minutes, content: await readFile(target) };
    }
  }
  // Storage: bytes at a path. How they reach a command is declared here, once, and never again.
  else if (action === 'put') {
    const parsed = parseArgs({ args, options: { env: { type: 'string' }, file: { type: 'string' }, type: { type: 'string' }, from: { type: 'string' }, secret: { type: 'boolean' } }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1) throw new Error('Usage: put <path> [--env NAME] [--file NAME] [--secret] [--type <media-type>] [--from <file>]   (bytes on stdin unless --from)');
    const content = parsed.values.from ? await readFile(parsed.values.from) : await readStdin();
    if (content.length > 1024 * 1024) throw new Error('put takes at most 1 MB. Larger files belong in the sharing space (share).');
    options = { path: parsed.positionals[0], content, query: { ...(parsed.values.env ? { env: parsed.values.env } : {}), ...(parsed.values.file ? { filename: parsed.values.file } : {}), ...(parsed.values.secret ? { secret: 'true' } : {}) },
      type: parsed.values.type || (parsed.values.from ? TYPES[extname(parsed.values.from).toLowerCase()] : null) || 'application/octet-stream' };
  }
  else if (action === 'get' || action === 'drop') {
    const parsed = parseArgs({ args, options: action === 'get' ? { out: { type: 'string' } } : {}, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1) throw new Error('Usage: ' + action + ' <path>' + (action === 'get' ? ' [--out <file>]' : ''));
    options = { path: parsed.positionals[0], out: parsed.values.out };
  }
  else if (action === 'list') {
    const parsed = parseArgs({ args, options: {}, strict: true, allowPositionals: true });
    if (parsed.positionals.length > 1) throw new Error('Usage: list [<path prefix>]');
    options = { prefix: parsed.positionals[0] };
  }
  else if (!(['adapters', 'credentials', 'shared', 'cancel', 'whoami', 'leave', 'request'].includes(action) && !args.length) && !(action === 'exec' && targets.length && new Set(targets).size === targets.length && command.length)) throw new Error('Invalid command. Use --help.');
  const url = new URL(process.env.FOUNDATION_URL || '');
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('FOUNDATION_URL must be an HTTPS origin (HTTP is allowed only on localhost).');
  // Without --adapter, connect asks for this key to be approved. With it, an approved key asks for a registration.
  if (action === 'connect' && !options.adapter && (options.purpose || options.guidance)) throw new Error('--purpose and --guide belong to a request that asks for something; add --adapter <id>, or use ask.');
  if (action === 'connect' && !options.adapter) { delete options.purpose; }
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const token = action === 'adapters' ? null : await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  const entryUrl = () => '/v1/entries/' + options.path.split('/').map(encodeURIComponent).join('/');
  const path = action === 'adapters' ? '/v1/adapters' : action === 'credentials' ? '/v1/credentials'
    : action === 'shared' ? '/v1/files' : action === 'link' ? '/v1/files/' + encodeURIComponent(options.id) + '/link'
    : action === 'share' ? '/v1/files?' + new URLSearchParams({ name: options.name, ...(options.minutes === undefined ? {} : { minutes: String(options.minutes) }) })
    : action === 'list' ? '/v1/entries' + (options.prefix ? '?' + new URLSearchParams({ prefix: options.prefix }) : '')
    : ['put', 'get', 'drop'].includes(action) ? entryUrl() + (action === 'put' && Object.keys(options.query).length ? '?' + new URLSearchParams(options.query) : '')
    : action === 'exec' ? '/v1/deliver' : ['whoami', 'leave', 'rename'].includes(action) ? '/v1/me' : action === 'cancel' || action === 'request' ? '/v1/access-requests/current' : '/v1/access-requests';
  const method = ['connect', 'ask', 'share', 'link'].includes(action) ? 'POST' : action === 'exec' ? 'POST' : action === 'put' ? 'PUT' : action === 'rename' ? 'PATCH' : ['cancel', 'leave', 'drop'].includes(action) ? 'DELETE' : 'GET';
  async function send(target, { timeout = 30_000, verb = method, payload, type = 'application/json', binary = false } = {}) {
    const response = await fetch(url.origin + target, { method: verb, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), 'content-type': type },
      ...(verb === 'GET' ? {} : { body: payload ?? '{}' }), redirect: 'error', signal: AbortSignal.timeout(timeout) });
    if (binary && response.ok) return Buffer.from(await response.arrayBuffer());
    const data = await response.json();
    if (!response.ok) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
    return data;
  }
  if (action === 'get') {
    const content = await send(path, { binary: true });
    if (options.out) { await writeFile(options.out, content, { mode: 0o600 }); console.log(JSON.stringify({ path: options.path, saved_to: options.out, bytes: content.length }, null, 2)); }
    else process.stdout.write(content);
    return;
  }
  const bodyFor = () => ['put', 'share'].includes(action) ? options.content
    : JSON.stringify(['connect', 'ask', 'rename'].includes(action) ? options : action === 'link' ? { minutes: options.minutes } : {});
  if (action !== 'exec') {
    const data = await send(path, { payload: bodyFor(), type: ['put', 'share'].includes(action) ? options.type : 'application/json' });
    if (action === 'leave') { console.log('Left Foundation: this access key was revoked. Delete ' + keyPath + ' if it is no longer needed.'); return; }
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  // Everything the command is to receive, gathered before it starts: kept things in one call, credentials one each.
  const issued = [];
  if (entryPaths.length) issued.push({ label: 'kept', ...(await send('/v1/deliver', { payload: JSON.stringify({ paths: entryPaths }) })) });
  for (const id of credentialIds) {
    const result = await send('/v1/credentials/' + id + '/deliver', { payload: '{}' });
    issued.push({ label: (result.credential?.adapter || result.credential?.service) + ':' + id, credentialId: id, ...result });
  }
  // What each credential sets is the server's to say; the runtime applies it and refuses collisions.
  const environment = { ...process.env };
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const owned = new Map(), files = [];
  const assign = (name, value, label) => {
    if (!validEnvName(name)) throw new Error('Foundation named a reserved environment variable (' + name + ') for ' + label + '.');
    if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || value.length > 16384) throw new Error('Foundation returned an invalid value for ' + name + ' (' + label + ').');
    if (owned.has(name) && owned.get(name) !== label) throw new Error('Two of them both set ' + name + ' (' + owned.get(name) + ' and ' + label + '). Choose one.');
    owned.set(name, label); environment[name] = value;
  };
  let expoSession = null;
  for (const item of issued) {
    const { label, delivery } = item;
    if (!delivery || typeof delivery.environment !== 'object' || !Array.isArray(delivery.files)) throw new Error('Foundation returned an invalid delivery.');
    if (delivery.expo_session) { if (issued.length > 1) throw new Error('An Expo login session cannot be combined with anything else.'); expoSession = delivery.expo_session; }
    for (const [name, value] of Object.entries(delivery.environment)) assign(name, value, label);
    for (const file of delivery.files) {
      if (typeof file.env !== 'string' || typeof file.filename !== 'string' || typeof file.content !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(file.filename) || file.filename.startsWith('.')) throw new Error('Foundation described an invalid file for ' + label + '.');
      files.push({ ...file, label });
    }
  }
  const usedIds = issued.map(item => item.credentialId).filter(Boolean);
  if (usedIds.length) environment.FOUNDATION_CREDENTIAL_IDS = usedIds.join(',');
  // Secret files live in a private directory for exactly as long as the command runs.
  let secretDir;
  if (files.length) {
    secretDir = await mkdtemp(join(process.env.XDG_RUNTIME_DIR && (await stat(process.env.XDG_RUNTIME_DIR).catch(() => null))?.isDirectory() ? process.env.XDG_RUNTIME_DIR : tmpdir(), 'foundation-'));
    await chmod(secretDir, 0o700);
    for (const file of files) {
      const target = join(secretDir, file.filename);
      await writeFile(target, file.encoding === 'base64' ? Buffer.from(file.content, 'base64') : file.content, { mode: 0o600, flag: 'wx' });
      assign(file.env, target, file.label);
    }
  }
  const cleanup = () => { if (secretDir) rmSync(secretDir, { recursive: true, force: true }); };
  process.once('exit', cleanup);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.once(signal, () => { cleanup(); process.exit(1); });
  try {
    const child = expoSession ? await spawnExpoSession(command, environment, expoSession) : spawn(command[0], command.slice(1), { stdio: 'inherit', env: environment, shell: false });
    process.exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (value, signal) => resolve(value ?? (signal ? 1 : 0))); });
  } finally { cleanup(); }
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check Foundation URL and network access.' : error.message); process.exitCode = 1; });
