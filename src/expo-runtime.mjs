import { spawn } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

// This isolates EAS/Expo's shared login file, not arbitrary untrusted programs.
// No HOME override, disk credential file, secret argv or global CLI login.
export async function spawnExpoSession(command, environment, session) {
  if (process.platform !== 'linux') throw new Error('Expo session execution requires Linux with bubblewrap.');
  const directory = join(homedir(), '.expo');
  try {
    const entry = await lstat(directory);
    if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error('Expo login directory must be a real directory. Shared login was not changed.');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const profile = session.profile;
  if (!profile || typeof profile.user_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(profile.user_id) || typeof profile.username !== 'string' || !profile.username || profile.username.length > 256 || /[\x00-\x1f\x7f]/.test(profile.username)) throw new Error('Foundation returned an invalid Expo session profile.');
  const auth = { sessionSecret: session.secret, userId: profile.user_id, username: profile.username, currentConnection: 'Username-Password-Authentication' };
  const bytes = Buffer.from(JSON.stringify({ auth }));
  const env = { ...environment };
  delete env.EXPO_TOKEN; delete env.EXPO_STAGING; delete env.EXPO_LOCAL;
  const child = spawn('/usr/bin/bwrap', ['--die-with-parent', '--new-session', '--unshare-pid', '--bind', '/', '/', '--proc', '/proc',
    '--size', '1048576', '--perms', '0700', '--tmpfs', directory, '--perms', '0600', '--file', '3', join(directory, 'state.json'), '--', ...command],
  { stdio: ['inherit', 'inherit', 'inherit', 'pipe'], env, shell: false });
  child.stdio[3].on('error', () => { bytes.fill(0); });
  child.stdio[3].end(bytes, () => { bytes.fill(0); });
  return child;
}
