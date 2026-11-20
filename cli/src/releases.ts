import { z } from 'zod';

export const packageName = '@tomato414941/foundation';
const stable = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

export function compareVersions(left: string, right: string) {
  const a = left.split('.').map(Number), b = right.split('.').map(Number);
  for (let index = 0; index < 3; index++) if (a[index] !== b[index]) return a[index]! - b[index]!;
  return 0;
}

// Names the CLI release a Foundation server was released with when it is not this one, and how to install that one.
export async function releaseNote(origin: string, current: string, fetcher: Fetcher = fetch) {
  let release: unknown;
  try {
    const response = await fetcher(new URL('/api/release', origin).href, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return null;
    release = await response.json();
  } catch { return null; }
  const parsed = z.object({ cliVersion: z.string().regex(stable) }).safeParse(release);
  if (!parsed.success) return null;
  const server = parsed.data.cliVersion, order = compareVersions(server, current);
  if (order === 0) return null;
  return order > 0
    ? 'This CLI is ' + current + ', and ' + origin + ' was released with CLI ' + server +
      '. Install it: npm install --global --ignore-scripts ' + packageName + '@' + server
    : 'This CLI is ' + current + ', newer than CLI ' + server + ', which ' + origin + ' was released with.';
}
