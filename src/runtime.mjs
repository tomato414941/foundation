import { open, mkdir, stat, mkdtemp, writeFile, chmod } from 'node:fs/promises';
import { rmSync } from 'node:fs';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { homedir, hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { spawnExpoSession } from './expo-runtime.mjs';
import { validEnvName, validRequestedEnvName } from './env-name.mjs';
import { guide } from './guide.mjs';

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
  let accountIds = [], issuance = {};
  if (action === 'exec' && separatorAt > 0) {
    const parsed = parseArgs({ args: args.slice(0, separatorAt), options: { duration: { type: 'string' } }, strict: true, allowPositionals: true });
    accountIds = parsed.positionals;
    if (parsed.values.duration !== undefined) {
      if (!/^\d{1,7}$/.test(parsed.values.duration) || Number(parsed.values.duration) < 1) throw new Error('--duration must be a positive number of seconds; AWS decides whether it is allowed.');
      issuance = { duration: Number(parsed.values.duration) };
    }
  }
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
    const { service, site, field = [], 'multiline-field': multiline = [], ...values } = parseArgs({ args, options: { adapter: { type: 'string' }, permission: { type: 'string' }, name: { type: 'string', default: hostname() + ' の ' + (agentName || 'AI') }, purpose: { type: 'string', default: '' }, guide: { type: 'string', default: '' }, valid: { type: 'string', default: '' }, service: { type: 'string' }, site: { type: 'string' }, field: { type: 'string', multiple: true }, 'multiline-field': { type: 'string', multiple: true } }, strict: true, allowPositionals: false }).values;
    options = values;
    if (options.guide) { options.guidance = options.guide; } delete options.guide;
    if (options.valid) { if (!/^\d{1,4}$/.test(options.valid)) throw new Error('--valid takes the number of minutes the link stays open (1-1440).'); options.valid_minutes = Number(options.valid); } delete options.valid;
    // The generic adapter: the runtime declares the service, where the key is made, and each value it wants as NAME[=label].
    if (service !== undefined || site !== undefined || field.length || multiline.length) {
      const declare = kind => text => { const at = text.indexOf('='), id = at < 0 ? text : text.slice(0, at); if (!validRequestedEnvName(id)) throw new Error('--field names are environment variables: UPPER_CASE and not reserved (' + id + ').'); return { id, label: at < 0 ? id : text.slice(at + 1), kind }; };
      if (!service || !site || !(field.length + multiline.length)) throw new Error('--service, --site (https) and at least one --field are required for a generic request.');
      if (options.adapter && options.adapter !== 'generic') throw new Error('--service, --site and --field belong to the generic adapter.');
      options.adapter = 'generic'; options.details = { service, site, fields: [...field.map(declare('line')), ...multiline.map(declare('multiline'))] };
    }
  }
  else if (action === 'rename') {
    if (args.length !== 1 || !args[0].trim() || args[0].length > 80) throw new Error('Usage: rename <new name> (1-80 characters).');
    options = { name: args[0].trim() };
  }
  else if (!(['adapters', 'accounts', 'cancel', 'whoami', 'leave', 'request'].includes(action) && !args.length) && !(action === 'exec' && accountIds.length && accountIds.every(id => /^[a-f0-9-]{36}$/.test(id)) && new Set(accountIds).size === accountIds.length && command.length)) throw new Error('Invalid command. Use --help.');
  const url = new URL(process.env.FOUNDATION_URL || '');
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('FOUNDATION_URL must be an HTTPS origin (HTTP is allowed only on localhost).');
  if (action === 'connect') {
    if (!options.adapter) throw new Error('Choose how to connect with --adapter <id>. Run adapters to see them.');
    if (!options.permission) {
      const response = await fetch(url.origin + '/v1/adapters', { redirect: 'error', signal: AbortSignal.timeout(30_000) });
      const catalog = await response.json();
      if (!response.ok || !Array.isArray(catalog.adapters)) throw new Error('Unable to discover Foundation adapters.');
      const adapter = catalog.adapters.find(item => item.id === options.adapter);
      if (!adapter?.available) throw new Error('This adapter is not available. Run adapters to see the ones that are.');
      if (adapter.permissions.length !== 1) throw new Error('This adapter has several permissions; choose one with --permission (' + adapter.permissions.map(permission => permission.id).join(' | ') + ').');
      options.permission = adapter.permissions[0].id;
    }
  }
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + (agentName ? '-' + agentName.toLowerCase().replace(/[^a-z0-9]+/g, '-') : '') + '.key');
  const token = action === 'adapters' ? null : await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  const path = action === 'adapters' ? '/v1/adapters' : action === 'accounts' ? '/v1/accounts' : action === 'exec' ? '/v1/accounts/' + accountIds[0] + '/credentials' : ['whoami', 'leave', 'rename'].includes(action) ? '/v1/me' : action === 'cancel' || action === 'request' ? '/v1/access-requests/current' : '/v1/access-requests';
  const method = action === 'connect' || action === 'exec' ? 'POST' : action === 'rename' ? 'PATCH' : action === 'cancel' || action === 'leave' ? 'DELETE' : 'GET';
  async function request(timeout = 30_000, target = path) {
    const response = await fetch(url.origin + target, { method, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), 'content-type': 'application/json' }, ...(method !== 'GET' ? { body: JSON.stringify(action === 'connect' || action === 'rename' ? options : action === 'exec' ? issuance : {}) } : {}), redirect: 'error', signal: AbortSignal.timeout(timeout) });
    const data = await response.json();
    if (!response.ok) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
    return data;
  }
  let data = await request();
  if (action === 'leave') { console.log('Left Foundation: this access key and its permissions were revoked. Delete ' + keyPath + ' if it is no longer needed.'); return; }
  if (action !== 'exec') { console.log(JSON.stringify(data, null, 2)); return; }
  const issued = [data];
  for (const id of accountIds.slice(1)) issued.push(await request(30_000, '/v1/accounts/' + id + '/credentials'));
  const environment = { ...process.env };
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const owned = new Map(), files = [];
  const assign = (name, value, account) => {
    if (!validEnvName(name)) throw new Error('Foundation named a reserved environment variable (' + name + ') for ' + account + '.');
    if (owned.has(name) && owned.get(name) !== account) throw new Error('Two connections both set ' + name + ' (' + owned.get(name) + ' and ' + account + '). Choose one of them.');
    owned.set(name, account); environment[name] = value;
  };
  let expoSession = false;
  for (const credential of issued) {
    const session = credential.credential_type === 'expo_session';
    const secretFile = credential.credential_type === 'private_key';
    const expiryValid = (['api_key', 'private_key'].includes(credential.credential_type) || session) && credential.expires_at === null || Number.isFinite(credential.expires_at) && credential.expires_at > Date.now();
    if (typeof credential.access_token !== 'string' || !credential.access_token || /\x00/.test(credential.access_token) || (!secretFile && /[\r\n]/.test(credential.access_token)) || !credential.account?.subject || !expiryValid) throw new Error('Foundation returned an invalid credential.');
    if (session) { if (issued.length > 1) throw new Error('An Expo login session cannot be combined with other connections.'); expoSession = true; }
    const label = credential.account.adapter + ':' + credential.account.id;
    if (credential === data) Object.assign(environment, { FOUNDATION_ACCESS_TOKEN: secretFile ? '' : credential.access_token, FOUNDATION_CREDENTIAL_TYPE: credential.credential_type || 'oauth2_access_token', FOUNDATION_ACCOUNT_ID: credential.account.id, FOUNDATION_ACCOUNT_LABEL: credential.account.label || credential.account.subject, FOUNDATION_ADAPTER: credential.account.adapter, FOUNDATION_TOKEN_EXPIRES_AT: credential.expires_at === null ? '' : String(credential.expires_at), FOUNDATION_API_BASE_URL: credential.api_base_url, FOUNDATION_AUTH_HEADER: session ? 'expo-session' : 'authorization' });
    // How each credential reaches the command is the server's to say; the runtime only applies it.
    if (credential.token_env != null) assign(credential.token_env, credential.access_token, label);
    if (credential.token_file) {
      const file = credential.token_file;
      if (typeof file.env !== 'string' || typeof file.filename !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(file.filename) || file.filename.startsWith('.')) throw new Error('Foundation described an invalid credential file for ' + label + '.');
      files.push({ env: file.env, filename: file.filename, content: credential.access_token, label });
    }
    for (const [name, value] of Object.entries(credential.environment || {})) {
      if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || value.length > 1024) throw new Error('Foundation returned an invalid environment value for ' + label + '.');
      assign(name, value, label);
    }
  }
  environment.FOUNDATION_ACCOUNT_IDS = issued.map(credential => credential.account.id).join(',');
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
    const child = expoSession ? await spawnExpoSession(command, environment, data) : spawn(command[0], command.slice(1), { stdio: 'inherit', env: environment, shell: false });
    process.exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (value, signal) => resolve(value ?? (signal ? 1 : 0))); });
  } finally { cleanup(); }
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check Foundation URL and network access.' : error.message); process.exitCode = 1; });
