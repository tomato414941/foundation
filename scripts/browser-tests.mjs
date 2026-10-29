import { execFile, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const recipe = join(root, 'scripts/browser');
const runId = randomUUID();
const container = 'foundation-browser-test-' + runId;
const image = 'foundation-browser-tests:' + runId;
let active, interrupted, started = false, removal;

async function removeContainer() {
  if (!started) return;
  removal ??= execute('docker', ['rm', '--force', container], { timeout: 10_000 }).catch(error => {
    if (!error.stderr?.includes('No such container')) throw error;
  });
  return removal;
}
function checkInterrupted() {
  if (interrupted) throw new Error('Browser tests interrupted.');
}
const handlers = ['SIGINT', 'SIGTERM', 'SIGHUP'].map(signal => {
  const handler = () => {
    interrupted ??= signal;
    active?.kill(signal);
    void removeContainer().catch(() => {});
  };
  process.on(signal, handler);
  return [signal, handler];
});
async function docker(args) {
  checkInterrupted();
  await new Promise((resolve, reject) => {
    active = spawn('docker', args, { cwd: root, stdio: 'inherit' });
    active.once('error', reject);
    active.once('close', (code, signal) => {
      active = undefined;
      if (code === 0) resolve();
      else reject(Object.assign(new Error('Browser test container command failed.'), {
        exitCode: signal ? 128 + constants.signals[signal] : code ?? 1,
      }));
    });
  });
  checkInterrupted();
}

try {
  // Each run owns its image reference; concurrent builds still share Docker's layer cache.
  await docker(['build', '--platform', 'linux/amd64', '--file', join(recipe, 'Dockerfile'), '--tag', image, recipe]);
  const environment = ['CI', 'TEST_DATABASE_URL', 'FOUNDATION_BROWSER_SHARD', 'FOUNDATION_TEST_PORT', 'FOUNDATION_UI_SERVER']
    .filter(name => process.env[name] !== undefined).flatMap(name => ['--env', name]);
  started = true;
  await docker(['run', '--rm', '--init', '--name', container, '--label', 'foundation.browser-tests=true',
    '--ipc=host', '--network=host', '--env', 'FOUNDATION_TEST_UID=' + process.getuid(), '--env', 'FOUNDATION_TEST_GID=' + process.getgid(),
    '--volume', root + ':/work', '--workdir', '/work', ...environment, image, 'python3', 'tests/browser.py', ...process.argv.slice(2)]);
} catch (error) {
  console.error(error.message);
  process.exitCode = error.exitCode ?? 1;
} finally {
  active = undefined;
  try { await removeContainer(); }
  catch (error) { console.error('Could not remove the browser test container: ' + error.message); process.exitCode ||= 1; }
  try { await execute('docker', ['image', 'rm', image], { timeout: 10_000 }); }
  catch (error) {
    if (!error.stderr?.includes('No such image')) {
      console.error('Could not remove the browser test image: ' + error.message);
      process.exitCode ||= 1;
    }
  }
  if (interrupted) process.exitCode = 128 + constants.signals[interrupted];
  for (const [signal, handler] of handlers) process.off(signal, handler);
}
