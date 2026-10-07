import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { z } from 'zod';

const Environment = z.object({
  DATABASE_URL: z.string().url(),
  FOUNDATION_ORIGIN: z.url().default('http://localhost:3417'),
  FOUNDATION_HOST: z.enum(['127.0.0.1', '0.0.0.0', '::1', '::']).default('127.0.0.1'),
  FOUNDATION_PROXY_ADDRESSES: z.string().default(''),
  FOUNDATION_PORT: z.coerce.number().int().min(1024).max(65535).default(3417),
  FOUNDATION_DATA: z.string().default('.foundation'),
  FOUNDATION_KEY: z.string().optional(),
  FOUNDATION_KMS_KEY: z.string().optional(),
  AWS_REGION: z.string().default('ap-northeast-1'),
  FOUNDATION_COMMIT: z.string().optional().transform((value) => value || undefined).pipe(z.string().regex(/^[0-9a-f]{40}$/).optional()),
  RESEND_API_KEY: z.string().default(''),
  FOUNDATION_MAIL_FROM: z.string().default(''),
  FOUNDATION_BILLING_MODE: z.enum(['required', 'included']).default('required'),
  FOUNDATION_INCLUDED_COMPUTE_SECONDS: z.coerce.number().int().nonnegative().default(360_000),
  FOUNDATION_INCLUDED_STORAGE_BYTES: z.coerce.number().int().nonnegative().default(21_474_836_480),
  FOUNDATION_INCLUDED_ENVIRONMENTS: z.coerce.number().int().nonnegative().default(3),
  STRIPE_SECRET_KEY: z.string().default(''),
  STRIPE_WEBHOOK_SECRET: z.string().default(''),
  STRIPE_COMPUTE_PRICE: z.string().default(''),
  STRIPE_STORAGE_PRICE: z.string().default(''),
  STRIPE_COMPUTE_METER: z.string().default('foundation_compute_seconds'),
  STRIPE_STORAGE_METER: z.string().default('foundation_storage_byte_hours'),
  FOUNDATION_BUCKET: z.string().default(''),
  FLY_API_TOKEN: z.string().default(''),
  FLY_APP: z.string().default(''),
  FLY_IMAGE: z.string().default(''),
  FLY_COMMAND_IMAGE: z.string().default(''),
  FLY_REGION: z.string().default('nrt'),
  FOUNDATION_LOG_LEVEL: z
    .enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent'])
    .default('info'),
});
export type Configuration = Awaited<ReturnType<typeof configuration>>;
export async function configuration(env: NodeJS.ProcessEnv = process.env) {
  const value = Environment.parse(env);
  const origin = new URL(value.FOUNDATION_ORIGIN);
  if (
    origin.pathname !== '/' ||
    origin.search ||
    origin.hash ||
    origin.username ||
    origin.password ||
    (!['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname) && origin.protocol !== 'https:')
  )
    throw new Error('FOUNDATION_ORIGIN must be an HTTPS origin (HTTP is allowed on localhost).');
  const dataDirectory = resolve(value.FOUNDATION_DATA);
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  let key = value.FOUNDATION_KEY;
  if (!key && !value.FOUNDATION_KMS_KEY) {
    const keyPath = resolve(dataDirectory, 'master-key');
    try {
      key = (await readFile(keyPath, 'utf8')).trim();
    } catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
      key = randomBytes(32).toString('base64url');
      try {
        await writeFile(keyPath, key, { mode: 0o600, flag: 'wx' });
      } catch (error) {
        if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
        key = (await readFile(keyPath, 'utf8')).trim();
      }
    }
    await chmod(keyPath, 0o600);
  }
  if (
    key &&
    (Buffer.from(key, 'base64url').length !== 32 ||
      Buffer.from(key, 'base64url').toString('base64url') !== key)
  )
    throw new Error('FOUNDATION_KEY must be a base64url-encoded 32-byte key.');
  return {
    ...value,
    origin: origin.origin,
    dataDirectory,
    key: key ? new Uint8Array(Buffer.from(key, 'base64url')) : null,
  };
}
