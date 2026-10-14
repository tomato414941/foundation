import { build } from 'esbuild';
import { chmod } from 'node:fs/promises';

await build({
  entryPoints: { cli: 'cli/src/main.ts', agent: 'cli/src/executor-main.ts' },
  bundle: true,
  platform: 'node',
  format: 'esm',
  banner: { js: "import { createRequire as foundationCreateRequire } from 'node:module'; const require = foundationCreateRequire(import.meta.url);" },
  target: 'node24',
  outdir: 'cli/dist',
  outExtension: { '.js': '.mjs' },
  minify: true,
  legalComments: 'eof',
});
await chmod('cli/dist/cli.mjs', 0o755);
await chmod('cli/dist/agent.mjs', 0o755);
