import { chmod, lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { KeyBinding, PrivateKeys } from '../../shared/authority.js';

const Identity = z
  .object({ origin: z.url(), principalId: z.uuid(), token: z.string().min(20),
    keys: PrivateKeys.nullable(), binding: KeyBinding.nullable() })
  .strict().refine(value => Boolean(value.keys) === Boolean(value.binding) &&
    (!value.binding || value.binding.principalId === value.principalId), 'Use the keys bound to this identity.');
export type IdentityConfig = z.infer<typeof Identity>;
export function configPath() {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'foundation', 'identity.json');
}
export function origin(value = process.env.FOUNDATION_ORIGIN || 'https://foundationsystems.app') {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Set FOUNDATION_ORIGIN to an HTTPS origin.');
  }
  if (
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    (url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))
  )
    throw new Error('Use an HTTPS origin, or HTTP on localhost.');
  return url.origin;
}
export async function readIdentity(override?: string): Promise<IdentityConfig> {
  let saved: IdentityConfig | undefined;
  try {
    const path = configPath(),
      stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('The identity must be a regular file.');
    if (process.platform !== 'win32' && stat.mode & 0o077) await chmod(path, 0o600);
    saved = Identity.parse(JSON.parse(await readFile(path, 'utf8')));
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT'))
      throw new Error('The saved identity could not be read. Check its contents and permissions.');
  }
  const destination = origin(override || process.env.FOUNDATION_ORIGIN || saved?.origin);
  const environmentToken = process.env.FOUNDATION_TOKEN;
  if (environmentToken) {
    if (override && process.env.FOUNDATION_ORIGIN && destination !== origin(process.env.FOUNDATION_ORIGIN))
      throw new Error('The environment identity belongs to a different origin.');
    const principalId = process.env.FOUNDATION_PRINCIPAL_ID,
      privateValue = process.env.FOUNDATION_PRIVATE_KEYS,
      publicValue = process.env.FOUNDATION_KEY_BINDING;
    if (!principalId) throw new Error('FOUNDATION_TOKEN requires FOUNDATION_PRINCIPAL_ID.');
    try {
      return Identity.parse({
        origin: destination,
        principalId,
        token: environmentToken,
        keys: privateValue ? JSON.parse(Buffer.from(privateValue, 'base64url').toString('utf8')) : null,
        binding: publicValue ? JSON.parse(Buffer.from(publicValue, 'base64url').toString('utf8')) : null,
      });
    } catch {
      throw new Error('The Foundation environment identity is invalid.');
    }
  }
  if (!saved) throw new Error('Run foundation init to register this machine.');
  if (destination !== origin(saved.origin))
    throw new Error(
      'This identity belongs to another origin. Use a separate XDG_CONFIG_HOME to initialize another server.',
    );
  return { ...saved, origin: destination };
}
export async function saveIdentity(identity: IdentityConfig) {
  await secureWrite(configPath(), JSON.stringify(Identity.parse(identity), null, 2) + '\n', false);
}
async function syncDirectory(path: string) {
  if (process.platform === 'win32') return;
  const directory = await open(path, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}
export async function secureWrite(path: string, content: string | Uint8Array, replace: boolean) {
  const absolute = resolve(path),
    directory = dirname(absolute);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if (!replace) {
    const file = await open(absolute, 'wx', 0o600);
    try {
      await file.writeFile(content);
      await file.sync();
    } finally {
      await file.close();
    }
    await syncDirectory(directory);
    return;
  }
  const temporary = join(directory, '.foundation-' + randomUUID());
  try {
    const file = await open(temporary, 'wx', 0o600);
    try {
      await file.writeFile(content);
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, absolute);
    await syncDirectory(directory);
  } finally {
    await rm(temporary, { force: true });
  }
}
