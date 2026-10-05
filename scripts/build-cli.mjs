import { build } from 'esbuild';
import { chmod } from 'node:fs/promises';

await build({
  entryPoints: ['cli/src/main.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile: 'cli/dist/cli.mjs',
  minify: true,
  legalComments: 'eof',
});
await chmod('cli/dist/cli.mjs', 0o755);
