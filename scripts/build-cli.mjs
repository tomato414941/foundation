import { build } from 'esbuild';
import { chmod } from 'node:fs/promises';

await build({
  entryPoints: ['cli/src/main.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  banner: { js: "import { createRequire as foundationCreateRequire } from 'node:module'; const require = foundationCreateRequire(import.meta.url);" },
  target: 'node24',
  outfile: 'cli/dist/cli.mjs',
  minify: true,
  legalComments: 'eof',
});
await chmod('cli/dist/cli.mjs', 0o755);
