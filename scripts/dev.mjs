import { spawn } from 'node:child_process';

const environment = {
  ...process.env,
  NODE_ENV: 'development',
  FOUNDATION_ORIGIN: process.env.FOUNDATION_ORIGIN || 'http://localhost:5173',
};
const programs = [
  ['node_modules/tsx/dist/cli.mjs', 'watch', 'server/main.ts'],
  ['node_modules/@react-router/dev/bin.cjs', 'dev'],
];
const children = programs.map((args) =>
  spawn(process.execPath, args, { env: environment, stdio: 'inherit' }),
);
let closing = false;
function stop(code) {
  if (closing) return;
  closing = true;
  process.exitCode = code;
  for (const child of children) child.kill('SIGTERM');
}
for (const child of children) {
  child.once('error', () => stop(1));
  child.once('exit', (code) => stop(code ?? 1));
}
process.once('SIGINT', () => stop(130));
process.once('SIGTERM', () => stop(143));
