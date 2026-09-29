import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { digest } from './crypto.mjs';

const require = createRequire(import.meta.url);
const files = new Map([
  ['/docs', [new URL('../web/docs.html', import.meta.url), 'text/html; charset=utf-8']],
  ['/docs/init.js', [new URL('../web/docs.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/docs/swagger-ui.css', [require.resolve('swagger-ui-dist/swagger-ui.css'), 'text/css; charset=utf-8']],
  ['/docs/swagger-ui-bundle.js', [require.resolve('swagger-ui-dist/swagger-ui-bundle.js'), 'text/javascript; charset=utf-8']],
]);
const loaded = new Map();
export async function serveDocs(req, res, path) {
  if (!files.has(path) || !['GET', 'HEAD'].includes(req.method)) return false;
  const [file, type] = files.get(path);
  if (!loaded.has(file)) loaded.set(file, readFile(file));
  const content = await loaded.get(file), tag = '"' + digest(content).slice(0, 32) + '"';
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('ETag', tag);
  // Swagger uses inline style attributes. Only the documentation page permits those; scripts stay self-only.
  if (path === '/docs') res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  if (req.headers['if-none-match'] === tag) { res.writeHead(304); res.end(); return true; }
  res.writeHead(200, { 'content-type': type });
  res.end(req.method === 'HEAD' ? undefined : content);
  return true;
}
