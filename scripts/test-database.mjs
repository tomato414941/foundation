import { execFile, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import pg from 'pg';

const execute = promisify(execFile);
const args = process.argv.slice(2);
let container;
let command;
let interrupted;
let forceKill;

function signalCommand(signal) {
  if (!command?.pid) return;
  try {
    if (process.platform === 'win32') command.kill(signal);
    else process.kill(-command.pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') console.error(error.message);
  }
}

const handlers = ['SIGINT', 'SIGTERM', 'SIGHUP'].map(signal => {
  const handler = () => {
    interrupted ??= signal;
    signalCommand(signal);
    if (command && !forceKill) {
      forceKill = setTimeout(() => signalCommand('SIGKILL'), 5_000);
      forceKill.unref();
    }
  };
  process.on(signal, handler);
  return [signal, handler];
});

function checkInterrupted() {
  if (interrupted) throw new Error('Test execution interrupted.');
}

async function docker(...arguments_) {
  const result = await execute('docker', arguments_, { timeout: 120_000 });
  return result.stdout.trim();
}

async function waitForDatabase(url) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    checkInterrupted();
    const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 1_000 });
    try {
      await client.connect();
      await client.query('SELECT 1');
      return;
    } catch {
      await delay(200);
    } finally {
      await client.end();
    }
  }
  throw new Error('The temporary test database did not become ready.');
}

try {
  if (!args.length) throw new Error('Usage: node scripts/test-database.mjs COMMAND [ARGS...]');
  const environment = { ...process.env };
  if (!environment.TEST_DATABASE_URL) {
    checkInterrupted();
    container = 'foundation-test-' + randomUUID();
    const password = randomBytes(24).toString('hex');
    await docker('run', '--detach', '--rm', '--name', container,
      '--label', 'foundation.test-database=true', '--publish', '127.0.0.1::5432',
      '--env', 'POSTGRES_USER=foundation', '--env', 'POSTGRES_PASSWORD=' + password,
      '--env', 'POSTGRES_DB=foundation_test', 'postgres:18-alpine');
    checkInterrupted();
    const address = await docker('port', container, '5432/tcp');
    const port = /^127\.0\.0\.1:(\d+)$/.exec(address)?.[1];
    if (!port) throw new Error('The test database has no localhost port.');
    environment.TEST_DATABASE_URL = `postgres://foundation:${password}@127.0.0.1:${port}/foundation_test`;
    await waitForDatabase(environment.TEST_DATABASE_URL);
    console.error('Started temporary test database ' + container + '.');
  }
  checkInterrupted();
  const result = await new Promise((resolve, reject) => {
    command = spawn(args[0], args.slice(1), {
      env: environment, stdio: 'inherit', detached: process.platform !== 'win32',
    });
    command.once('error', reject);
    command.once('close', (code, signal) => resolve({ code, signal }));
  });
  process.exitCode = result.signal ? 128 + constants.signals[result.signal] : result.code ?? 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  command = undefined;
  clearTimeout(forceKill);
  if (container) {
    try {
      await docker('rm', '--force', '--volumes', container);
      console.error('Removed temporary test database ' + container + '.');
    } catch (error) {
      if (!error.stderr?.includes('No such container')) {
        console.error('Could not remove the temporary test database: ' + error.message);
        process.exitCode ||= 1;
      }
    }
  }
  if (interrupted) process.exitCode = 128 + constants.signals[interrupted];
  for (const [signal, handler] of handlers) process.off(signal, handler);
}
