import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor } from './authorization.js';
import type { Audit } from './audit.js';
import type { Confirmations } from './confirmations.js';
import type { Resources, ResourceRow } from './resources.js';
import { Name, SSHHostData, SSHKeyData } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import type { ConfirmationOperation } from '../shared/confirmations.js';
import { AuthorizedKeysFile, SSHAccount, SSHAddress, SSHFrom, SSHPublicKey, sshKeyText } from '../shared/ssh.js';
import { authorizedKeyLine, fingerprintOf, lineFingerprint } from '../shared/ssh-access.js';
import type { SSHPlan, SSHReport } from '../shared/ssh-access.js';
import { fail, required } from './errors.js';

export const SSHKeyInput = z.object({
  name: Name, publicKey: SSHPublicKey, purpose: z.string().max(500).default(''), privateKeyId: z.uuid().nullable().default(null),
}).strict();
export const SSHHostInput = z.object({
  name: Name, address: SSHAddress, port: z.number().int().min(1).max(65535).default(22),
  hostKeys: z.array(SSHPublicKey).min(1).max(16), authorizedKeysFile: AuthorizedKeysFile.default('.ssh/authorized_keys'),
}).strict();
export const SSHHostChange = SSHHostInput.omit({ name: true }).partial().extend({ version: z.number().int().positive() }).strict();
export const SSHGrant = z.object({
  hostId: z.uuid(), keyId: z.uuid(), account: SSHAccount, expiresAt: z.iso.datetime().nullable().default(null),
  from: SSHFrom.nullable().default(null),
}).strict();
export const SSHAccessQuery = z.object({
  hostId: z.uuid().optional(), keyId: z.uuid().optional(),
  status: z.enum(['applied', 'pending', 'removed', 'remains_unmanaged']).optional(),
}).strict();
export const SSHAuthorizationView = z.object({
  id: z.uuid(), hostId: z.uuid(), keyId: z.uuid(), account: SSHAccount,
  expiresAt: z.iso.datetime().nullable(), from: z.string().nullable(),
  desired: z.enum(['present', 'absent']), expired: z.boolean(),
  observed: z.enum(['unknown', 'present', 'different', 'absent']), unmanaged: z.boolean(),
  // applied: the server shows the line; removed: the server shows the key gone; remains_unmanaged: removed here, but
  // the server still lets the key in outside the managed lines; pending: the server has not shown what was decided.
  status: z.enum(['applied', 'pending', 'removed', 'remains_unmanaged']),
  grantedBy: z.uuid(), grantedAt: z.iso.datetime(), revokedBy: z.uuid().nullable(), revokedAt: z.iso.datetime().nullable(),
  observedAt: z.iso.datetime().nullable(),
  key: z.object({ name: z.string(), ownerId: z.uuid(), fingerprint: z.string(), revoked: z.boolean() }).nullable(),
  host: z.object({ name: z.string(), address: z.string(), port: z.number().int() }).nullable(),
  attempt: z.object({ outcome: z.string().nullable(), message: z.string().nullable(), attemptedAt: z.iso.datetime().nullable(),
    verifiedAt: z.iso.datetime().nullable() }),
}).strict();
export const SSHHostAccountView = z.object({
  account: SSHAccount, outcome: z.string().nullable(), message: z.string().nullable(),
  attemptedAt: z.iso.datetime().nullable(), verifiedAt: z.iso.datetime().nullable(),
  unmanaged: z.array(z.object({ fingerprint: z.string(), keyId: z.uuid().nullable() })),
}).strict();

interface AuthorizationRow {
  id: string; host_id: string; key_id: string; account: string; expires_at: Date | null; from_hosts: string | null;
  desired: 'present' | 'absent'; observed: 'unknown' | 'present' | 'different' | 'absent'; unmanaged: boolean;
  observed_at: Date | null; granted_by: string; granted_at: Date; revoked_by: string | null; revoked_at: Date | null;
}
interface AccountRow {
  host_id: string; account: string; generation: number; outcome: string | null; message: string | null;
  attempted_at: Date | null; verified_at: Date | null; unmanaged: string[];
}
type KeyData = z.infer<typeof SSHKeyData>;
type HostData = z.infer<typeof SSHHostData>;

// The authorizations whose key a server may still let in: until a server shows the key gone, outside the managed lines
// as well, what was decided for it is followed, and what holds it is kept.
export const stillLetIn = "NOT (observed='absent' AND NOT unmanaged AND (desired='absent' OR coalesce(expires_at<=now(),false)))";
// Whether an authorization lets its key in now, and how far the server shows what was decided.
const wanted = (row: AuthorizationRow) => row.desired === 'present' && !(row.expires_at && row.expires_at <= new Date());
function status(row: AuthorizationRow) {
  if (wanted(row)) return row.observed === 'present' ? 'applied' : 'pending';
  if (row.observed !== 'absent') return 'pending';
  return row.unmanaged ? 'remains_unmanaged' : 'removed';
}
const sortedKeys = (keys: string[]) => [...new Set(keys.map(key => sshKeyText(key).publicKey))].sort();
// Where a host is reached, which keys prove it, and which file is written decide where keys are let in, so changing
// any of them is confirmed for the whole of what the host becomes, from the version it was changed from.
function hostOperation(host: ResourceRow, change: Omit<z.output<typeof SSHHostChange>, 'version'>): ConfirmationOperation | null {
  const previous = SSHHostData.parse(host.data);
  const next = { ...previous, ...change, hostKeys: sortedKeys(change.hostKeys ?? previous.hostKeys) };
  if (JSON.stringify(next) === JSON.stringify(previous)) return null;
  return { action: 'ssh.hostChange', principalId: host.owner_id, hostId: host.id, version: host.version, address: next.address,
    port: next.port, hostKeys: next.hostKeys, authorizedKeysFile: next.authorizedKeysFile };
}
// Taking a key out of an account and revoking a key everywhere are confirmed too, so that a token alone changes neither.
const revokeOperation = (host: ResourceRow, row: AuthorizationRow): ConfirmationOperation => ({
  action: 'ssh.revoke', principalId: host.owner_id, authorizationId: row.id, hostId: row.host_id, keyId: row.key_id, account: row.account,
});
const keyRevokeOperation = (key: ResourceRow): ConfirmationOperation => ({ action: 'ssh.keyRevoke', principalId: key.owner_id, keyId: key.id });
// A server that no longer exists cannot be checked, so a host whose authorizations were all taken out is deleted with
// them once whoever deletes it confirms that, without the server showing the keys gone.
const hostDeleteOperation = (host: ResourceRow): ConfirmationOperation => ({ action: 'ssh.hostDelete', principalId: host.owner_id, hostId: host.id });
// Letting a key into a server account is confirmed by whoever lets it in, as adding a way in is.
const grantOperation = (host: ResourceRow, value: z.output<typeof SSHGrant>): ConfirmationOperation => ({
  action: 'ssh.grant', principalId: host.owner_id, hostId: host.id, keyId: value.keyId, account: value.account,
  expiresAt: value.expiresAt, from: value.from,
});
// A plan read before what it was made from changed is applied and reported no more: each change moves the generation of
// the accounts it touches, and a report names the generation its plan was read at.
const advance = (connection: Queryable, hostIds: string[], account: string | null = null) => connection.query(
  'UPDATE ssh_host_accounts SET generation=generation+1 WHERE host_id=ANY($1::uuid[]) AND ($2::text IS NULL OR account=$2)',
  [hostIds, account]);

// The SSH keys principals hold and the servers whose accounts let them in. What each account lets in is decided here
// and applied by a client that can sign in to the server, which reports what the server shows afterwards; the server
// keeps no private keys. Lines Foundation did not write are left as they are and reported only by fingerprint.
export class SSHAccess {
  constructor(readonly db: Database, readonly resources: Resources, readonly audit: Audit, readonly confirmations: Confirmations) {}
  private get authorization() { return this.resources.authorization; }
  private async row(id: string, kind: 'ssh_key' | 'ssh_host', connection: Queryable = this.db.pool, lock = '') {
    const row = await this.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 AND kind=$2' + lock, [id, kind], connection);
    if (!row) fail(404, 'not_found', kind === 'ssh_key' ? 'This SSH key does not exist.' : 'This SSH host does not exist.');
    return row;
  }

  async createKey(actor: Actor, ownerId: string, input: z.input<typeof SSHKeyInput>) {
    const value = SSHKeyInput.parse(input), key = sshKeyText(value.publicKey);
    return this.db.transaction(async connection => {
      if (!await this.authorization.canCreate(actor, ownerId, 'ssh_key', connection))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      if (value.privateKeyId) {
        const variable = await this.resources.get(value.privateKeyId, connection);
        if (variable.kind !== 'variable' || variable.owner_id !== ownerId)
          fail(400, 'invalid_private_key', 'Keep the private key as a variable of the same owner.');
        await this.authorization.requireResource(actor, variable, 'read', connection);
      }
      const data: KeyData = { publicKey: key.publicKey, algorithm: key.algorithm, fingerprint: fingerprintOf(key.key),
        purpose: value.purpose, privateKeyId: value.privateKeyId, revokedAt: null };
      const row = await this.resources.insert(ownerId, 'ssh_key', value.name, data,
        { references: value.privateKeyId ? [value.privateKeyId] : [] }, connection);
      await this.audit.record(ownerId, actor.id, 'ssh.key.create', row.id, { fingerprint: data.fingerprint }, connection);
      return row;
    });
  }
  async keyRevokeConfirmation(id: string) {
    const key = await this.row(id, 'ssh_key');
    return SSHKeyData.parse(key.data).revokedAt ? null : keyRevokeOperation(key);
  }
  // Takes the key out of every account that lets it in, and keeps it from being let in again.
  async revokeKey(actor: Actor, id: string) {
    return this.db.transaction(async connection => {
      const row = await this.row(id, 'ssh_key', connection, ' FOR UPDATE');
      await this.authorization.requireResource(actor, row, 'update', connection);
      const data = SSHKeyData.parse(row.data);
      if (data.revokedAt) return row;
      await this.confirmations.consume(connection, actor, keyRevokeOperation(row));
      const updated = await this.resources.update(row, { data: { ...data, revokedAt: new Date().toISOString() } }, connection);
      const revoked = await this.db.all<{ host_id: string; account: string }>(
        "UPDATE ssh_authorizations SET desired='absent',revoked_by=$2,revoked_at=now() WHERE key_id=$1 AND desired='present' RETURNING host_id,account",
        [id, actor.id], connection);
      for (const { host_id, account } of revoked) await advance(connection, [host_id], account);
      await this.audit.record(row.owner_id, actor.id, 'ssh.key.revoke', id, {}, connection);
      return updated;
    });
  }

  async createHost(actor: Actor, ownerId: string, input: z.input<typeof SSHHostInput>) {
    const { name, ...value } = SSHHostInput.parse(input);
    return this.db.transaction(async connection => {
      if (!await this.authorization.canCreate(actor, ownerId, 'ssh_host', connection))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      const data: HostData = { ...value, hostKeys: sortedKeys(value.hostKeys) };
      const row = await this.resources.insert(ownerId, 'ssh_host', name, data, {}, connection);
      await this.audit.record(ownerId, actor.id, 'ssh.host.create', row.id, {}, connection);
      return row;
    });
  }
  async hostConfirmation(id: string, input: z.input<typeof SSHHostChange>) {
    const { version: _version, ...change } = SSHHostChange.parse(input);
    return hostOperation(await this.row(id, 'ssh_host'), change);
  }
  async updateHost(actor: Actor, id: string, input: z.input<typeof SSHHostChange>) {
    const { version, ...change } = SSHHostChange.parse(input);
    return this.db.transaction(async connection => {
      const row = await this.row(id, 'ssh_host', connection, ' FOR UPDATE');
      await this.authorization.requireResource(actor, row, 'update', connection);
      if (row.version !== version) fail(409, 'changed', 'This SSH host changed. Reload it before saving.');
      const previous = SSHHostData.parse(row.data);
      const data: HostData = { ...previous, ...change, ...(change.hostKeys ? { hostKeys: sortedKeys(change.hostKeys) } : {}) };
      const confirmation = hostOperation(row, change);
      if (confirmation) await this.confirmations.consume(connection, actor, confirmation);
      // Another file, or a server proving itself with none of the keys it did, shows nothing of what was applied before,
      // so neither is taken on while a key may still be let in there. Another address or port reaches the same server,
      // which its host keys prove.
      const moved = data.authorizedKeysFile !== previous.authorizedKeysFile ||
        !data.hostKeys.some(key => previous.hostKeys.includes(key));
      if (moved && await this.db.one(
        'SELECT 1 FROM ssh_authorizations WHERE host_id=$1 AND ' + stillLetIn + ' LIMIT 1', [id], connection))
        fail(409, 'ssh_access_remaining', 'Remove its SSH authorizations and check the server before changing the authorized keys file or replacing every host key.');
      await advance(connection, [id]);
      const updated = await this.resources.update(row, { data }, connection);
      await this.audit.record(row.owner_id, actor.id, 'ssh.host.update', id,
        { hostKeys: JSON.stringify(data.hostKeys) !== JSON.stringify(previous.hostKeys), location: data.address !== previous.address || data.port !== previous.port ||
          data.authorizedKeysFile !== previous.authorizedKeysFile }, connection);
      return updated;
    });
  }

  private unchecked(hostId: string, connection: Queryable) {
    return this.db.all<AuthorizationRow>('SELECT * FROM ssh_authorizations WHERE host_id=$1 AND ' + stillLetIn, [hostId], connection);
  }
  async deleteConfirmation(id: string) {
    const row = await this.db.one<ResourceRow>("SELECT * FROM resources WHERE id=$1 AND kind='ssh_host'", [id]);
    const remaining = row ? await this.unchecked(id, this.db.pool) : [];
    return remaining.length && !remaining.some(wanted) ? hostDeleteOperation(row!) : null;
  }
  async deleteHost(actor: Actor, id: string) {
    return this.db.transaction(async connection => {
      const row = await this.row(id, 'ssh_host', connection, ' FOR UPDATE');
      await this.authorization.requireResource(actor, row, 'delete', connection);
      const remaining = await this.unchecked(id, connection);
      if (remaining.some(wanted)) fail(409, 'ssh_access_remaining', 'Remove its SSH authorizations before deleting it.');
      if (remaining.length) {
        await this.confirmations.consume(connection, actor, hostDeleteOperation(row));
        await connection.query('DELETE FROM ssh_authorizations WHERE host_id=$1', [id]);
        await this.audit.record(row.owner_id, actor.id, 'ssh.host.forget', id, { authorizations: remaining.length }, connection);
      }
      await this.resources.delete(actor, row, connection);
    });
  }

  async grantConfirmation(input: z.input<typeof SSHGrant>) {
    const value = SSHGrant.parse(input);
    return grantOperation(await this.row(value.hostId, 'ssh_host'), value);
  }
  async grant(actor: Actor, input: z.input<typeof SSHGrant>) {
    const value = SSHGrant.parse(input);
    if (value.expiresAt && Date.parse(value.expiresAt) <= Date.now()) fail(400, 'invalid_expiry', 'Choose a time in the future.');
    return this.db.transaction(async connection => {
      const host = await this.row(value.hostId, 'ssh_host', connection, ' FOR UPDATE');
      const key = await this.row(value.keyId, 'ssh_key', connection, ' FOR SHARE');
      await this.authorization.requireResource(actor, host, 'update', connection);
      await this.authorization.requireResource(actor, key, 'read', connection);
      const data = SSHKeyData.parse(key.data);
      if (data.revokedAt) fail(409, 'ssh_key_revoked', 'This SSH key was revoked. Register a new key.');
      const same = await this.db.one(
        `SELECT 1 FROM ssh_authorizations a JOIN resources k ON k.id=a.key_id WHERE a.host_id=$1 AND a.account=$2
         AND a.key_id<>$3 AND a.desired='present' AND k.data->>'fingerprint'=$4`,
        [value.hostId, value.account, value.keyId, data.fingerprint], connection);
      if (same) fail(409, 'ssh_key_duplicate', 'Another registration of this public key already lets it into this account.');
      await this.confirmations.consume(connection, actor, grantOperation(host, value));
      const row = required(await this.db.one<AuthorizationRow>(
        `INSERT INTO ssh_authorizations(id,host_id,key_id,account,expires_at,from_hosts,desired,granted_by)
         VALUES($1,$2,$3,$4,$5,$6,'present',$7)
         ON CONFLICT (host_id,key_id,account) DO UPDATE SET expires_at=EXCLUDED.expires_at,from_hosts=EXCLUDED.from_hosts,
           desired='present',granted_by=EXCLUDED.granted_by,granted_at=now(),revoked_by=NULL,revoked_at=NULL,
           observed=CASE WHEN ssh_authorizations.expires_at IS NOT DISTINCT FROM EXCLUDED.expires_at
             AND ssh_authorizations.from_hosts IS NOT DISTINCT FROM EXCLUDED.from_hosts THEN ssh_authorizations.observed ELSE 'unknown' END
         RETURNING *`,
        [randomUUID(), value.hostId, value.keyId, value.account, value.expiresAt, value.from, actor.id], connection));
      await connection.query(
        'INSERT INTO ssh_host_accounts(host_id,account) VALUES($1,$2) ON CONFLICT (host_id,account) DO UPDATE SET generation=ssh_host_accounts.generation+1',
        [value.hostId, value.account]);
      await this.audit.record(host.owner_id, actor.id, 'ssh.access.grant', row.id,
        { hostId: value.hostId, keyId: value.keyId, account: value.account }, connection);
      return (await this.views(actor, [row], connection))[0]!;
    });
  }
  async revokeConfirmation(id: string) {
    const row = await this.db.one<AuthorizationRow>('SELECT * FROM ssh_authorizations WHERE id=$1', [id]);
    return row?.desired === 'present' ? revokeOperation(await this.row(row.host_id, 'ssh_host'), row) : null;
  }
  // Takes a key out of an account: whoever manages the server or uses the key may. The authorization stays until the
  // server shows the key gone.
  async revoke(actor: Actor, id: string) {
    return this.db.transaction(async connection => {
      const row = await this.db.one<AuthorizationRow>('SELECT * FROM ssh_authorizations WHERE id=$1 FOR UPDATE', [id], connection);
      if (!row) fail(404, 'not_found', 'This SSH authorization does not exist.');
      const host = await this.row(row.host_id, 'ssh_host', connection), key = await this.row(row.key_id, 'ssh_key', connection);
      if (!await this.authorization.can(actor, host, 'update', connection) && !await this.authorization.can(actor, key, 'use', connection))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      if (row.desired === 'present') await this.confirmations.consume(connection, actor, revokeOperation(host, row));
      const updated = row.desired === 'absent' ? row : required(await this.db.one<AuthorizationRow>(
        "UPDATE ssh_authorizations SET desired='absent',revoked_by=$2,revoked_at=now() WHERE id=$1 RETURNING *", [id, actor.id], connection));
      if (row.desired === 'present') await advance(connection, [row.host_id], row.account);
      if (row.desired === 'present')
        await this.audit.record(host.owner_id, actor.id, 'ssh.access.revoke', id, { hostId: row.host_id, keyId: row.key_id, account: row.account }, connection);
      return (await this.views(actor, [updated], connection))[0]!;
    });
  }

  // The authorizations on servers or keys the actor can read, with what it may see of each side.
  async list(actor: Actor, query: z.input<typeof SSHAccessQuery>) {
    const value = SSHAccessQuery.parse(query);
    const [hosts, keys] = await Promise.all([this.authorization.find(actor.id, 'ssh_host', 'read'),
      this.authorization.find(actor.id, 'ssh_key', 'read')]);
    if (actor.requestId) return { items: [] };
    const rows = await this.db.all<AuthorizationRow>(
      `SELECT * FROM ssh_authorizations WHERE (host_id=ANY($1::uuid[]) OR key_id=ANY($2::uuid[]))
       AND ($3::uuid IS NULL OR host_id=$3) AND ($4::uuid IS NULL OR key_id=$4) ORDER BY host_id,account,granted_at,id`,
      [hosts, keys, value.hostId ?? null, value.keyId ?? null]);
    const items = await this.views(actor, rows, this.db.pool, { hosts, keys });
    return { items: value.status ? items.filter(item => item.status === value.status) : items };
  }
  private async views(actor: Actor, rows: AuthorizationRow[], connection: Queryable,
    readable?: { hosts: string[]; keys: string[] }) {
    const hosts = readable?.hosts ?? await this.authorization.find(actor.id, 'ssh_host', 'read', connection);
    const keys = readable?.keys ?? await this.authorization.find(actor.id, 'ssh_key', 'read', connection);
    const resources = new Map((await this.db.all<ResourceRow>('SELECT * FROM resources WHERE id=ANY($1::uuid[])',
      [[...new Set(rows.flatMap(row => [row.host_id, row.key_id]))]], connection)).map(row => [row.id, row]));
    const accounts = new Map((await this.db.all<AccountRow>(
      'SELECT * FROM ssh_host_accounts WHERE host_id=ANY($1::uuid[])', [[...new Set(rows.map(row => row.host_id))]], connection))
      .map(row => [row.host_id + ' ' + row.account, row]));
    return rows.map(row => {
      const host = resources.get(row.host_id)!, key = resources.get(row.key_id)!, attempt = accounts.get(row.host_id + ' ' + row.account);
      const hostData = SSHHostData.parse(host.data), keyData = SSHKeyData.parse(key.data);
      return SSHAuthorizationView.parse({
        id: row.id, hostId: row.host_id, keyId: row.key_id, account: row.account,
        expiresAt: row.expires_at ? iso(row.expires_at) : null, from: row.from_hosts, desired: row.desired,
        expired: !!row.expires_at && row.expires_at <= new Date(), observed: row.observed, unmanaged: row.unmanaged,
        status: status(row), grantedBy: row.granted_by, grantedAt: iso(row.granted_at), revokedBy: row.revoked_by,
        revokedAt: row.revoked_at ? iso(row.revoked_at) : null, observedAt: row.observed_at ? iso(row.observed_at) : null,
        key: keys.includes(key.id)
          ? { name: key.name, ownerId: key.owner_id, fingerprint: keyData.fingerprint, revoked: !!keyData.revokedAt } : null,
        host: hosts.includes(host.id) ? { name: host.name, address: hostData.address, port: hostData.port } : null,
        attempt: { outcome: attempt?.outcome ?? null, message: attempt?.message ?? null,
          attemptedAt: attempt?.attempted_at ? iso(attempt.attempted_at) : null,
          verifiedAt: attempt?.verified_at ? iso(attempt.verified_at) : null },
      });
    });
  }
  // What each account of the server last showed, with keys let in outside the managed lines named when the actor can
  // read them.
  async accounts(actor: Actor, hostId: string) {
    const host = await this.row(hostId, 'ssh_host');
    await this.authorization.requireResource(actor, host, 'read');
    const rows = await this.db.all<AccountRow>('SELECT * FROM ssh_host_accounts WHERE host_id=$1 ORDER BY account', [hostId]);
    const keys = await this.db.all<{ id: string; fingerprint: string }>(
      "SELECT id,data->>'fingerprint' AS fingerprint FROM resources WHERE kind='ssh_key' AND id=ANY($1::uuid[]) ORDER BY id",
      [await this.authorization.find(actor.id, 'ssh_key', 'read')]);
    return { items: rows.map(row => SSHHostAccountView.parse({
      account: row.account, outcome: row.outcome, message: row.message,
      attemptedAt: row.attempted_at ? iso(row.attempted_at) : null, verifiedAt: row.verified_at ? iso(row.verified_at) : null,
      unmanaged: row.unmanaged.map(fingerprint => ({ fingerprint, keyId: keys.find(key => key.fingerprint === fingerprint)?.id ?? null })),
    })) };
  }

  // What a client applies: for each account still to be followed, the lines the managed part should hold. Those who
  // manage the server see the public keys it lets in, as they would on the server.
  async plan(actor: Actor, hostId: string): Promise<SSHPlan> {
    await this.authorization.requireResource(actor, await this.row(hostId, 'ssh_host'), 'update');
    // Every account ever let into stays followed, so that a check finds a key let in again outside the managed lines.
    // The generations are read first: a change made while the rest is read moves them past this plan.
    const accounts = await this.db.all<AccountRow>('SELECT * FROM ssh_host_accounts WHERE host_id=$1 ORDER BY account', [hostId]);
    const data = SSHHostData.parse((await this.row(hostId, 'ssh_host')).data);
    const rows = await this.db.all<AuthorizationRow & { public_key: string }>(
      `SELECT a.*,k.data->>'publicKey' AS public_key FROM ssh_authorizations a JOIN resources k ON k.id=a.key_id
       WHERE a.host_id=$1 ORDER BY a.account,a.id`, [hostId]);
    return { hostId, address: data.address, port: data.port, hostKeys: data.hostKeys,
      accounts: accounts.map(({ account, generation }) => ({ account, file: data.authorizedKeysFile.replaceAll('%u', account),
        generation,
        lines: rows.filter(row => row.account === account && wanted(row)).map(row => authorizedKeyLine(
          { id: row.id, publicKey: row.public_key, expiresAt: row.expires_at, from: row.from_hosts })) })) };
  }
  // Records what a client found on an account. A verified report says, for each authorization, whether the managed
  // lines hold its line and whether its key is let in elsewhere; any other outcome keeps what was last shown.
  async report(actor: Actor, hostId: string, input: SSHReport) {
    return this.db.transaction(async connection => {
      const host = await this.row(hostId, 'ssh_host', connection, ' FOR SHARE');
      await this.authorization.requireResource(actor, host, 'update', connection);
      const account = await this.db.one<AccountRow>(
        'SELECT * FROM ssh_host_accounts WHERE host_id=$1 AND account=$2 FOR UPDATE', [hostId, input.account], connection);
      if (!account || account.generation !== input.generation)
        fail(409, 'ssh_report_stale', 'The account was reported again since this plan. Read the plan and check the server again.');
      const verified = input.outcome === 'verified';
      await connection.query(
        `UPDATE ssh_host_accounts SET generation=generation+1,outcome=$3,message=$4,attempted_at=now(),
         verified_at=CASE WHEN $5 THEN now() ELSE verified_at END,unmanaged=CASE WHEN $5 THEN $6::jsonb ELSE unmanaged END
         WHERE host_id=$1 AND account=$2`,
        [hostId, input.account, input.outcome, verified ? null : input.message ?? null, verified,
          JSON.stringify(verified ? input.unmanaged : [])]);
      if (input.outcome === 'verified') {
        const managed = new Set(input.managed), found = new Set(input.managed.map(lineFingerprint));
        const rows = await this.db.all<AuthorizationRow & { public_key: string; fingerprint: string }>(
          `SELECT a.*,k.data->>'publicKey' AS public_key,k.data->>'fingerprint' AS fingerprint FROM ssh_authorizations a
           JOIN resources k ON k.id=a.key_id WHERE a.host_id=$1 AND a.account=$2 FOR UPDATE OF a`, [hostId, input.account], connection);
        for (const row of rows) {
          const line = authorizedKeyLine({ id: row.id, publicKey: row.public_key, expiresAt: row.expires_at, from: row.from_hosts });
          await connection.query('UPDATE ssh_authorizations SET observed=$2,unmanaged=$3,observed_at=now() WHERE id=$1',
            [row.id, managed.has(line) ? 'present' : found.has(row.fingerprint) ? 'different' : 'absent',
              input.unmanaged.includes(row.fingerprint)]);
        }
      }
      await this.audit.record(host.owner_id, actor.id, 'ssh.host.report', hostId,
        { account: input.account, outcome: input.outcome } satisfies Record<string, JsonValue>, connection);
      return { ok: true as const };
    });
  }
}
