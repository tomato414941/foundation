import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import fastifyStatic from '@fastify/static';
import type { ApiApp } from './app.js';

export async function web(app: ApiApp) {
  const directory = resolve('dist/web/client');
  let html: string;
  try {
    html = await readFile(resolve(directory, 'index.html'), 'utf8');
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return;
    throw error;
  }
  await app.register(fastifyStatic, {
    root: resolve(directory, 'assets'),
    prefix: '/assets/',
    maxAge: '1y',
    immutable: true,
    index: false,
    dotfiles: 'deny',
  });
  for (const [name, type] of [
    ['logo.svg', 'image/svg+xml'],
    ['service-logos.svg', 'image/svg+xml'],
    ['favicon.png', 'image/png'],
    ['apple-touch-icon.png', 'image/png'],
  ] as const) {
    const content = await readFile(resolve(directory, name));
    app.get('/' + name, { schema: { hide: true } }, (_request, reply) =>
      reply.type(type).header('cache-control', 'public, max-age=3600').send(content),
    );
  }
  app.setNotFoundHandler((request, reply) => {
    if (!['GET', 'HEAD'].includes(request.method) || /^\/(?:api|assets)(?:\/|$)/.test(request.url))
      return reply.code(404).send({ error: { code: 'not_found', message: 'This endpoint does not exist.' } });
    const nonce = randomBytes(24).toString('base64');
    return reply
      .type('text/html; charset=utf-8')
      .header('cache-control', 'no-store')
      .header(
        'content-security-policy',
        [
          "default-src 'self'",
          `script-src 'self' 'nonce-${nonce}'`,
          `style-src 'self' 'nonce-${nonce}'`,
          "style-src-attr 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "font-src 'self'",
          "connect-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "frame-ancestors 'none'",
          "form-action 'self'",
        ].join('; '),
      )
      .send(html.replaceAll('__FOUNDATION_NONCE__', nonce));
  });
}
