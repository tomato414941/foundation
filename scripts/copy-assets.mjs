import { cp, mkdir, readdir } from 'node:fs/promises';

await mkdir(new URL('../dist/server/', import.meta.url), { recursive: true });
for (const path of ['schema.sql', 'authorization.zed', 'aws-connection.yaml', 'catalog']) {
  await cp(
    new URL('../server/' + path, import.meta.url),
    new URL('../dist/server/' + path, import.meta.url),
    { recursive: true },
  );
}
await mkdir(new URL('../dist/server/migrations/', import.meta.url), { recursive: true });
for (const name of (await readdir(new URL('../server/migrations/', import.meta.url))).filter(name => name.endsWith('.sql')))
  await cp(new URL('../server/migrations/' + name, import.meta.url), new URL('../dist/server/migrations/' + name, import.meta.url));
