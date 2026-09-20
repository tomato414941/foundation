import { open, mkdir, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';

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
  const [accountId, separator, ...command] = args;
  if (action === '--help' || !action) {
    console.log('Usage: node src/runtime.mjs providers\n       node src/runtime.mjs connect [--provider <id>] [--mode <permission-id>] [--name <name>] [--purpose <purpose>]\n       node src/runtime.mjs status\n       node src/runtime.mjs cancel\n       node src/runtime.mjs accounts\n       node src/runtime.mjs exec <account-id> -- <command> [args...]\nEnvironment: FOUNDATION_URL; optional FOUNDATION_RUNTIME_KEY_FILE\nconnect selects the first available provider and its first permission unless specified, saves a private runtime key and prints an approval URL plus confirmation code.\nAfter the user approves, run status, then accounts or exec. No key copying is needed.\nDefault key: ~/.local/state/foundation/<origin-hash>.key (private, per Foundation origin).\nChild environment: FOUNDATION_ACCESS_TOKEN, FOUNDATION_CREDENTIAL_TYPE, FOUNDATION_ACCOUNT_ID, FOUNDATION_ACCOUNT_LABEL, FOUNDATION_PROVIDER, FOUNDATION_TOKEN_EXPIRES_AT, FOUNDATION_API_BASE_URL\nGmail also receives: GOOGLE_OAUTH_ACCESS_TOKEN, GMAIL_ACCOUNT_EMAIL, GOOGLE_OAUTH_EXPIRES_AT\nOpenRouter also receives: OPENROUTER_API_KEY\nAn empty FOUNDATION_TOKEN_EXPIRES_AT means the API key has no reported expiry, not a short-lived token. Foundation revocation stops future delivery; already delivered keys require provider-side deletion. Model calls can incur charges.');
    console.log('Expo also receives: EXPO_TOKEN (only in the selected child process; no eas login or shared Expo state change). Expo builds and other operations may incur charges.');
    return;
  }
  let options;
  if (action === 'connect') options = parseArgs({ args, options: { provider: { type: 'string' }, name: { type: 'string', default: hostname() + ' のAI' }, purpose: { type: 'string', default: '' }, mode: { type: 'string' } }, strict: true, allowPositionals: false }).values;
  else if (!(['providers', 'accounts', 'status', 'cancel'].includes(action) && !args.length) && !(action === 'exec' && /^[a-f0-9-]{36}$/.test(accountId || '') && separator === '--' && command.length)) throw new Error('Invalid command. Use --help.');
  const url = new URL(process.env.FOUNDATION_URL || '');
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('FOUNDATION_URL must be an HTTPS origin (HTTP is allowed only on localhost).');
  if (action === 'connect' && (!options.provider || !options.mode)) {
    const response = await fetch(url.origin + '/v1/providers', { redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const catalog = await response.json();
    if (!response.ok || !Array.isArray(catalog.providers)) throw new Error('Unable to discover Foundation providers.');
    const provider = options.provider ? catalog.providers.find(item => item.id === options.provider) : catalog.providers.find(item => item.available);
    if (!provider?.available) throw new Error('This provider is not available. Run providers to check available connections.');
    options.provider = provider.id; options.mode ||= provider.permissions[0]?.id;
  }
  const keyPath = process.env.FOUNDATION_RUNTIME_KEY_FILE || join(homedir(), '.local', 'state', 'foundation', createHash('sha256').update(url.origin).digest('hex').slice(0, 24) + '.key');
  const token = action === 'providers' ? null : await runtimeKey(keyPath, action === 'connect', !process.env.FOUNDATION_RUNTIME_KEY_FILE);
  const path = action === 'providers' ? '/v1/providers' : action === 'accounts' ? '/v1/accounts' : action === 'exec' ? '/v1/accounts/' + accountId + '/credentials' : '/v1/access-requests' + (action === 'connect' ? '' : '/current');
  const method = action === 'connect' || action === 'exec' ? 'POST' : action === 'cancel' ? 'DELETE' : 'GET';
  const response = await fetch(url.origin + path, { method, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), 'content-type': 'application/json' }, ...(method !== 'GET' ? { body: JSON.stringify(action === 'connect' ? options : {}) } : {}), redirect: 'error', signal: AbortSignal.timeout(30_000) });
  const data = await response.json();
  if (!response.ok) throw new Error('Foundation request failed (' + response.status + ', ' + (data.error?.code || 'unknown') + '). ' + (data.error?.message || 'Check the connection and runtime permission.'));
  if (action !== 'exec') { console.log(JSON.stringify(data, null, 2)); return; }
  const expiryValid = data.credential_type === 'api_key' && data.expires_at === null || Number.isFinite(data.expires_at) && data.expires_at > Date.now();
  if (typeof data.access_token !== 'string' || !data.access_token || /[\r\n\x00]/.test(data.access_token) || !data.account?.email || !expiryValid) throw new Error('Foundation returned an invalid credential.');
  const environment = { ...process.env, FOUNDATION_ACCESS_TOKEN: data.access_token, FOUNDATION_CREDENTIAL_TYPE: data.credential_type || 'oauth2_access_token', FOUNDATION_ACCOUNT_ID: data.account.id, FOUNDATION_ACCOUNT_LABEL: data.account.label || data.account.email, FOUNDATION_PROVIDER: data.account.provider, FOUNDATION_TOKEN_EXPIRES_AT: data.expires_at === null ? '' : String(data.expires_at), FOUNDATION_API_BASE_URL: data.api_base_url };
  delete environment.GOOGLE_OAUTH_ACCESS_TOKEN; delete environment.GMAIL_ACCOUNT_EMAIL; delete environment.GOOGLE_OAUTH_EXPIRES_AT;
  delete environment.OPENROUTER_API_KEY; delete environment.EXPO_TOKEN;
  if (data.account.provider === 'gmail') Object.assign(environment, { GOOGLE_OAUTH_ACCESS_TOKEN: data.access_token, GMAIL_ACCOUNT_EMAIL: data.account.email, GOOGLE_OAUTH_EXPIRES_AT: String(data.expires_at) });
  if (data.account.provider === 'openrouter') environment.OPENROUTER_API_KEY = data.access_token;
  if (data.account.provider === 'expo') environment.EXPO_TOKEN = data.access_token;
  delete environment.FOUNDATION_RUNTIME_KEY_FILE;
  const child = spawn(command[0], command.slice(1), { stdio: 'inherit', env: environment, shell: false });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (value, signal) => resolve(value ?? (signal ? 1 : 0))); });
  process.exitCode = code;
}
main().catch((error) => { console.error(error instanceof TypeError ? 'Unable to connect. Check Foundation URL and network access.' : error.message); process.exitCode = 1; });
