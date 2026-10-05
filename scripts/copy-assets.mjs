import { cp, mkdir } from 'node:fs/promises';

await mkdir(new URL('../dist/server/', import.meta.url), { recursive: true });
for (const path of ['schema.sql', 'catalog']) {
  await cp(new URL('../server/' + path, import.meta.url), new URL('../dist/server/' + path, import.meta.url), { recursive: true });
}
