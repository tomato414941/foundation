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
  const credentialIds = action === 'exec' && separatorAt > 0 ? args.slice(0, separatorAt) : [];
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
    const { service, site, field = [], 'multiline-field': multiline = [], ...values } = parseArgs({ args, options: { adapter: { type: 'string' }, name: { type: 'string', default: hostname() + ' の ' + (agentName || 'AI') }, purpose: { type: 'string', default: '' }, guide: { type: 'string', default: '' }, valid: { type: 'string', default: '' }, service: { type: 'string' }, site: { type: 'string' }, field: { type: 'string', multiple: true }, 'multiline-field': { type: 'string', multiple: true } }, strict: true, allowPositionals: false }).values;
    options = values;
    if (options.guide) { options.guidance = options.guide; } delete options.guide;
    if (options.valid) { if (!/^\d{1,4}$/.test(options.valid)) throw new Error('--valid takes the number of minutes the link stays open (1-1440).'); options.valid_minutes = Number(options.valid); } delete options.valid;
    // The generic adapter: the runtime declares the service, where the key is made, and each value it wants as NAME[=label].
    if (service !== undefined || site !== undefined || field.length || multiline.length) {
      const declare = kind => text => { const at = text.indexOf('='), id = at < 0 ? text : text.slice(0, at); if (!validEnvName(id)) throw new Error('--field names are environment variables: UPPER_CASE and not reserved (' + id + ').'); return { id, label: at < 0 ? id : text.slice(at + 1), kind }; };
      if (!service || !site || !(field.length + multiline.length)) throw new Error('--service, --site (https) and at least one --field are required for a generic request.');
      if (options.adapter && options.adapter !== 'generic') throw new Error('--service, --site and --field belong to the generic adapter.');
      options.adapter = 'generic'; options.details = { service, site, fields: [...field.map(declare('line')), ...multiline.map(declare('multiline'))] };
    }
  }
  else if (action === 'rename') {
    if (args.length !== 1 || !args[0].trim() || args[0].length > 80) throw new Error('Usage: rename <new name> (1-80 characters).');
    options = { name: args[0].trim() };
  }
  // The file space: put a file and get a link to it, list what is there, or link a file again.
  else if (action === 'put' || action === 'link') {
    const parsed = parseArgs({ args, options: { minutes: { type: 'string' }, ...(action === 'put' ? { type: { type: 'string' } } : {}) }, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1) throw new Error(action === 'put' ? 'Usage: put <file> [--type <content-type>] [--minutes <n>]' : 'Usage: link <file-id> [--minutes <n>]');
    const minutes = minutesOption(parsed.values.minutes), target = parsed.positionals[0];
    if (action === 'link') options = { id: target, ...(minutes === undefined ? {} : { minutes }) };
    else {
      const info = await stat(target);
      if (!info.isFile() || info.size > 5 * 1024 * 1024) throw new Error('put takes a regular file of at most 5 MB.');
      options = { name: basename(target), type: parsed.values.type || TYPES[extname(target).toLowerCase()] || 'application/octet-stream', minutes, content: await readFile(target) };
    }
  }
  // Storage on its own: values a command will read as environment variables, and documents read back whole.
  else if (action === 'keep') {
    const parsed = parseArgs({ args, options: { service: { type: 'string' }, value: { type: 'string', multiple: true, default: [] } }, strict: true, allowPositionals: false }).values;
    if (!parsed.service || !parsed.value.length) throw new Error('Usage: keep --service <name> --value NAME=VALUE [--value ...]');
    options = { service: parsed.service, values: Object.fromEntries(parsed.value.map(pair => {
      const at = pair.indexOf('=');
      if (at < 1 || !validEnvName(pair.slice(0, at))) throw new Error('--value takes NAME=VALUE, where NAME is an environment variable name (' + pair.slice(0, Math.max(at, 0)) + ').');
      return [pair.slice(0, at), pair.slice(at + 1)];
    })) };
  }
  else if (action === 'forget') {
    if (args.length !== 1 || !/^[a-f0-9-]{36}$/.test(args[0])) throw new Error('Usage: forget <value-id>');
    options = { id: args[0] };
  }
  else if (action === 'write' || action === 'read' || action === 'erase') {
    const parsed = parseArgs({ args, options: action === 'write' ? { file: { type: 'string' } } : {}, strict: true, allowPositionals: true });
    if (parsed.positionals.length !== 1 || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(parsed.positionals[0])) throw new Error('Usage: ' + action + ' <collection>/<name>' + (action === 'write' ? ' [--file <path>] (JSON on stdin by default)' : ''));
    options = { path: parsed.positionals[0] };
    if (action === 'write') {
      const text = parsed.values.file ? await readFile(parsed.values.file, 'utf8') : await new Promise((resolve, reject) => { let input = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', part => { input += part; }); process.stdin.once('end', () => resolve(input)); process.stdin.once('error', reject); });
      try { options.body = JSON.parse(text); } catch { throw new Error('write takes JSON, on stdin or from --file.'); }
    }
  }
  else if (action === 'documents') {
    const parsed = parseArgs({ args, options: { collection: { type: 'string' } }, strict: true, allowPositionals: false }).values;
    options = { collection: parsed.collection };
  }
  else if (!(['adapters', 'credentials', 'files', 'values', 'cancel', 'whoami', 'leave', 'request'].includes(action) && !args.length) && !(action === 'exec' && credentialIds.length && credentialIds.every(id => /^[a-f0-9-]{36}$/.test(id)) && new Set(credentialIds).size === credentialIds.length && command.length)) throw new Error('Invalid command. Use --help.');
  const url = new URL(process.env.FOUNDATION_URL || '');
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('FOUNDATION_URL must be an HTTPS origin (HTTP is allowed only on localhost).');
  // Without --adapter, connect asks for this key to be approved. With it, an approved key asks for a registration.
  if (action === 'connect' && !options.adapter && (options.purpose || options.guidance)) throw new Error('--purpose and --guide belong to a registration request; add --adapter <id>.');
  if (action === 'connect' && !options.adapter) { delete options.purpose; }
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const token = action === 'adapters' ? null : await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  const documentPath = () => '/v1/documents/' + options.path.split('/').map(encodeURIComponent).join('/');
  const path = action === 'adapters' ? '/v1/adapters' : action === 'credentials' ? '/v1/credentials' : action === 'files' ? '/v1/files' : action === 'link' ? '/v1/files/' + encodeURIComponent(options.id) + '/link'
    : action === 'put' ? '/v1/files?' + new URLSearchParams({ name: options.name, ...(options.minutes === undefined ? {} : { minutes: String(options.minutes) }) })
    : action === 'values' || action === 'keep' ? '/v1/vault' : action === 'forget' ? '/v1/vault/' + options.id
    : action === 'documents' ? '/v1/documents' + (options.collection ? '?' + new URLSearchParams({ collection: options.collection }) : '') : ['write', 'read', 'erase'].includes(action) ? documentPath()
    : action === 'exec' ? '/v1/credentials/' + credentialIds[0] + '/deliver' : ['whoami', 'leave', 'rename'].includes(action) ? '/v1/me' : action === 'cancel' || action === 'request' ? '/v1/access-requests/current' : '/v1/access-requests';
  const method = ['connect', 'exec', 'put', 'link', 'keep'].includes(action) ? 'POST' : action === 'write' ? 'PUT' : action === 'rename' ? 'PATCH' : ['cancel', 'leave', 'forget', 'erase'].includes(action) ? 'DELETE' : 'GET';
  async function request(timeout = 30_000, target = path) {
    const payload = action === 'put' ? options.content
      : JSON.stringify(['connect', 'rename', 'keep'].includes(action) ? options : action === 'write' ? { body: options.body } : action === 'link' ? { minutes: options.minutes } : {});
    const response = await fetch(url.origin + target, { method, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), 'content-type': action === 'put' ? options.type : 'application/json' }, ...(method !== 'GET' ? { body: payload } : {}), redirect: 'error', signal: AbortSignal.timeout(timeout) });
    const data = await response.json();
    if (!response.ok) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
    return data;
  }
  let data = await request();
  if (action === 'leave') { console.log('Left Foundation: this access key was revoked. Delete ' + keyPath + ' if it is no longer needed.'); return; }
  if (action !== 'exec') { console.log(JSON.stringify(data, null, 2)); return; }
  const issued = [data];
  for (const id of credentialIds.slice(1)) issued.push(await request(30_000, '/v1/credentials/' + id + '/deliver'));
  // What each credential sets is the server's to say; the runtime applies it and refuses collisions.
  const environment = { ...process.env };
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const owned = new Map(), files = [];
  const assign = (name, value, label) => {
    if (!validEnvName(name)) throw new Error('Foundation named a reserved environment variable (' + name + ') for ' + label + '.');
    if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || value.length > 16384) throw new Error('Foundation returned an invalid value for ' + name + ' (' + label + ').');
    if (owned.has(name) && owned.get(name) !== label) throw new Error('Two credentials both set ' + name + ' (' + owned.get(name) + ' and ' + label + '). Choose one of them.');
    owned.set(name, label); environment[name] = value;
  };
  let expoSession = null;
  for (const item of issued) {
    const label = (item.credential?.adapter || item.credential?.service) + ':' + item.credential?.id, delivery = item.delivery;
    if (!item.credential?.id || !delivery || typeof delivery.environment !== 'object' || !Array.isArray(delivery.files)) throw new Error('Foundation returned an invalid delivery.');
    if (delivery.expo_session) { if (issued.length > 1) throw new Error('An Expo login session cannot be combined with other credentials.'); expoSession = delivery.expo_session; }
    for (const [name, value] of Object.entries(delivery.environment)) assign(name, value, label);
    for (const file of delivery.files) {
      if (typeof file.env !== 'string' || typeof file.filename !== 'string' || typeof file.content !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(file.filename) || file.filename.startsWith('.')) throw new Error('Foundation described an invalid credential file for ' + label + '.');
      files.push({ ...file, label });
    }
  }
  environment.FOUNDATION_CREDENTIAL_IDS = issued.map(item => item.credential.id).join(',');
  // Secret files live in a private directory for exactly as long as the command runs.
  let secretDir;
  if (files.length) {
    secretDir = await mkdtemp(join(process.env.XDG_RUNTIME_DIR && (await stat(process.env.XDG_RUNTIME_DIR).catch(() => null))?.isDirectory() ? process.env.XDG_RUNTIME_DIR : tmpdir(), 'foundation-'));
    await chmod(secretDir, 0o700);
    for (const file of files) {
      const target = join(secretDir, file.filename);
      await writeFile(target, file.content, { mode: 0o600, flag: 'wx' });
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
