import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';

const VerifiedRelease = z.object({ commit: z.string().regex(/^[a-f0-9]{40}$/),
  cliVersion: z.string().regex(/^\d+\.\d+\.\d+$/), cliSha256: z.string().regex(/^[a-f0-9]{64}$/),
  agentSha256: z.string().regex(/^[a-f0-9]{64}$/),
  verifiedAt: z.iso.datetime() });

export async function verifiedRelease(directory: string) {
  try {
    const release = VerifiedRelease.parse(JSON.parse(await readFile(join(directory, 'release.json'), 'utf8')));
    return release.commit === process.env.FOUNDATION_RELEASE_COMMIT ? release : null;
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null;
    throw error;
  }
}
