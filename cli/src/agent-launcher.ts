import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export function launchAgent(mode: 'start' | 'managed', options?: object): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../dist/agent.mjs', import.meta.url)), mode], {
      stdio: 'inherit', env: { ...process.env, ...(options ? { FOUNDATION_AGENT_OPTIONS: JSON.stringify(options) } : {}) },
    });
    const interrupt = () => child.kill('SIGINT'), terminate = () => child.kill('SIGTERM');
    process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
    child.once('close', () => { process.off('SIGINT', interrupt); process.off('SIGTERM', terminate); });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
}
