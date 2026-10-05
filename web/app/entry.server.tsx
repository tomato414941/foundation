import { renderToReadableStream } from 'react-dom/server';
import { ServerRouter } from 'react-router';
import type { EntryContext } from 'react-router';

export default async function handleRequest(request: Request, status: number, headers: Headers, context: EntryContext) {
  const nonce = '__FOUNDATION_NONCE__';
  const stream = await renderToReadableStream(<ServerRouter context={context} url={request.url} nonce={nonce} />, { nonce, signal: request.signal });
  await stream.allReady;
  headers.set('content-type', 'text/html; charset=utf-8');
  return new Response(stream, { status, headers });
}
