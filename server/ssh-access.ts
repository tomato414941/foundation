import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor } from './authorization.js';
import type { Audit } from './audit.js';
import type { Resources, ResourceRow } from './resources.js';
import { Name, SSHHostData, SSHKeyData } from '../shared/contracts.js';
import { SSHAccount, SSHAddress, SSHPublicKey, sshKeyText } from '../shared/ssh.js';
import { fail, required } from './errors.js';

export const SSHKeyInput = z.object({
  name: Name, publicKey: SSHPublicKey, purpose: z.string().max(500).default(''), privateKeyId: z.uuid().nullable().default(null),
}).strict();
export const SSHHostInput = z.object({
  name: Name, address: SSHAddress, port: z.number().int().min(1).max(65535).default(22),
}).strict();
export const SSHHostChange = SSHHostInput.omit({ name: true }).partial().extend({ version: z.number().int().positive() }).strict();
export const SSHGrant = z.object({ hostId: z.uuid(), keyId: z.uuid(), account: SSHAccount }).strict();
export const SSHAccessQuery = z.object({ hostId: z.uuid().optional(), keyId: z.uuid().optional() }).strict();
export const SSHAuthorizationView = z.object({
  id: z.uuid(), hostId: z.uuid(), keyId: z.uuid(), account: SSHAccount, grantedBy: z.uuid(), grantedAt: z.iso.datetime(),
  key: z.object({ name: z.string(), ownerId: z.uuid(), fingerprint: z.string() }).nullable(),
  host: z.object({ name: z.string(), address: z.string(), port: z.number().int() }).nullable(),
}).strict();

interface AuthorizationRow {
  id: string; host_id: string; key_id: string; account: string; granted_by: string; granted_at: Date;
}
type KeyData = z.infer<typeof SSHKeyData>;

// The fingerprint OpenSSH shows for a public key.
export const fingerprintOf = (key: string) =>
  'SHA256:' + createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64').replace(/=+$/, '');

// The SSH keys principals hold, the servers they sign in to, and which key signs in to which account of a server. This
// is a record only: Foundation does not change or read the servers, and the server keeps no private keys.
export class SSHAccess {
  constructor(readonly db: Database, readonly resources: Resources, readonly audit: Audit) {}
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
        purpose: value.purpose, privateKeyId: value.privateKeyId };
      const row = await this.resources.insert(ownerId, 'ssh_key', value.name, data,
        { references: value.privateKeyId ? [value.privateKeyId] : [] }, connection);
      await this.audit.record(ownerId, actor.id, 'ssh.key.create', row.id, { fingerprint: data.fingerprint }, connection);
      return row;
    });
  }

  async createHost(actor: Actor, ownerId: string, input: z.input<typeof SSHHostInput>) {
    const { name, ...data } = SSHHostInput.parse(input);
    return this.db.transaction(async connection => {
      if (!await this.authorization.canCreate(actor, ownerId, 'ssh_host', connection))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      const row = await this.resources.insert(ownerId, 'ssh_host', name, data, {}, connection);
      await this.audit.record(ownerId, actor.id, 'ssh.host.create', row.id, {}, connection);
      return row;
    });
  }
  async updateHost(actor: Actor, id: string, input: z.input<typeof SSHHostChange>) {
    const { version, ...change } = SSHHostChange.parse(input);
    return this.db.transaction(async connection => {
      const row = await this.row(id, 'ssh_host', connection, ' FOR UPDATE');
      await this.authorization.requireResource(actor, row, 'update', connection);
      if (row.version !== version) fail(409, 'changed', 'This SSH host changed. Reload it before saving.');
      const updated = await this.resources.update(row, { data: { ...SSHHostData.parse(row.data), ...change } }, connection);
      await this.audit.record(row.owner_id, actor.id, 'ssh.host.update', id, {}, connection);
      return updated;
    });
  }

  // Records that a key signs in to an account of a server. Whoever manages the server records it, for a key they can read.
  async grant(actor: Actor, input: z.input<typeof SSHGrant>) {
    const value = SSHGrant.parse(input);
    return this.db.transaction(async connection => {
      const host = await this.row(value.hostId, 'ssh_host', connection, ' FOR UPDATE');
      const key = await this.row(value.keyId, 'ssh_key', connection, ' FOR SHARE');
      await this.authorization.requireResource(actor, host, 'update', connection);
      await this.authorization.requireResource(actor, key, 'read', connection);
      const same = await this.db.one(
        `SELECT 1 FROM ssh_authorizations a JOIN resources k ON k.id=a.key_id WHERE a.host_id=$1 AND a.account=$2
         AND a.key_id<>$3 AND k.data->>'fingerprint'=$4`,
        [value.hostId, value.account, value.keyId, SSHKeyData.parse(key.data).fingerprint], connection);
      if (same) fail(409, 'ssh_key_duplicate', 'Another registration of this public key already signs in to this account.');
      const row = required(await this.db.one<AuthorizationRow>(
        `INSERT INTO ssh_authorizations(id,host_id,key_id,account,granted_by) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT (host_id,key_id,account) DO UPDATE SET granted_by=EXCLUDED.granted_by,granted_at=now() RETURNING *`,
        [randomUUID(), value.hostId, value.keyId, value.account, actor.id], connection));
      await this.audit.record(host.owner_id, actor.id, 'ssh.access.grant', row.id,
        { hostId: value.hostId, keyId: value.keyId, account: value.account }, connection);
      return (await this.views(actor, [row], connection))[0]!;
    });
  }
  // Removes the record that a key signs in to an account: whoever manages the server or uses the key may.
  async revoke(actor: Actor, id: string) {
    return this.db.transaction(async connection => {
      const row = await this.db.one<AuthorizationRow>('SELECT * FROM ssh_authorizations WHERE id=$1 FOR UPDATE', [id], connection);
      if (!row) fail(404, 'not_found', 'This SSH authorization does not exist.');
      const host = await this.row(row.host_id, 'ssh_host', connection), key = await this.row(row.key_id, 'ssh_key', connection);
      if (!await this.authorization.can(actor, host, 'update', connection) && !await this.authorization.can(actor, key, 'use', connection))
        fail(403, 'forbidden', 'You do not have permission to perform this action.');
      await connection.query('DELETE FROM ssh_authorizations WHERE id=$1', [id]);
      await this.audit.record(host.owner_id, actor.id, 'ssh.access.revoke', id,
        { hostId: row.host_id, keyId: row.key_id, account: row.account }, connection);
      return { ok: true as const };
    });
  }

  // The records on servers or keys the actor can read, with what it may see of each side.
  async list(actor: Actor, query: z.input<typeof SSHAccessQuery>) {
    const value = SSHAccessQuery.parse(query);
    const [hosts, keys] = await Promise.all([this.authorization.find(actor.id, 'ssh_host', 'read'),
      this.authorization.find(actor.id, 'ssh_key', 'read')]);
    const rows = await this.db.all<AuthorizationRow>(
      `SELECT * FROM ssh_authorizations WHERE (host_id=ANY($1::uuid[]) OR key_id=ANY($2::uuid[]))
       AND ($3::uuid IS NULL OR host_id=$3) AND ($4::uuid IS NULL OR key_id=$4) ORDER BY host_id,account,granted_at,id`,
      [hosts, keys, value.hostId ?? null, value.keyId ?? null]);
    return { items: await this.views(actor, rows, this.db.pool, { hosts, keys }) };
  }
  private async views(actor: Actor, rows: AuthorizationRow[], connection: Queryable,
    readable?: { hosts: string[]; keys: string[] }) {
    const hosts = readable?.hosts ?? await this.authorization.find(actor.id, 'ssh_host', 'read', connection);
    const keys = readable?.keys ?? await this.authorization.find(actor.id, 'ssh_key', 'read', connection);
    const resources = new Map((await this.db.all<ResourceRow>('SELECT * FROM resources WHERE id=ANY($1::uuid[])',
      [[...new Set(rows.flatMap(row => [row.host_id, row.key_id]))]], connection)).map(row => [row.id, row]));
    return rows.map(row => {
      const host = resources.get(row.host_id)!, key = resources.get(row.key_id)!;
      const hostData = SSHHostData.parse(host.data), keyData = SSHKeyData.parse(key.data);
      return SSHAuthorizationView.parse({
        id: row.id, hostId: row.host_id, keyId: row.key_id, account: row.account,
        grantedBy: row.granted_by, grantedAt: iso(row.granted_at),
        key: keys.includes(key.id) ? { name: key.name, ownerId: key.owner_id, fingerprint: keyData.fingerprint } : null,
        host: hosts.includes(host.id) ? { name: host.name, address: hostData.address, port: hostData.port } : null,
      });
    });
  }
}
