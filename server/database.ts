import { readFile } from 'node:fs/promises';
import pg from 'pg';
import type { PoolClient, QueryResultRow } from 'pg';

export type Queryable = Pick<pg.Pool, 'query'>;
export class Database {
  readonly pool: pg.Pool;
  constructor(url: string, options: { max?: number; schema?: string } = {}) {
    if (options.schema && !/^[a-z][a-z0-9_]*$/.test(options.schema))
      throw new Error('Invalid database schema');
    this.pool = new pg.Pool({
      connectionString: url,
      max: options.max ?? 12,
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 30_000,
      options: `-c statement_timeout=30000${options.schema ? ' -c search_path=' + options.schema : ''}`,
    });
  }
  async initialize() {
    const schema = await readFile(new URL('./schema.sql', import.meta.url), 'utf8');
    await this.transaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(736023741)');
      await carryOverLines(client);
      await client.query(schema);
      const notifications = await client.query(
        "SELECT 1 FROM schema_migrations WHERE name='remove-outbound-webhooks'",
      );
      if (!notifications.rowCount) {
        await client.query('DROP TABLE IF EXISTS webhooks');
        await client.query('ALTER TABLE integration_settings DROP COLUMN IF EXISTS webhook_secret');
        await client.query("UPDATE integration_settings SET settings=settings-'webhookUrl' WHERE settings ? 'webhookUrl'");
        await client.query("INSERT INTO schema_migrations(name) VALUES('remove-outbound-webhooks')");
      }
    });
  }
  async all<T extends QueryResultRow>(
    sql: string,
    values: unknown[] = [],
    connection: Queryable = this.pool,
  ): Promise<T[]> {
    return (await connection.query<T>(sql, values)).rows;
  }
  async one<T extends QueryResultRow>(
    sql: string,
    values: unknown[] = [],
    connection: Queryable = this.pool,
  ): Promise<T | undefined> {
    return (await this.all<T>(sql, values, connection))[0];
  }
  async transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  async close() {
    await this.pool.end();
  }
}
export const iso = (value: Date | string) =>
  value instanceof Date ? value.toISOString() : new Date(value).toISOString();

// Until the lines moved into one table, owners were relation rows and single actions were kept as lists in grants and
// principal_grants. A database in that shape is carried over once, before the schema is applied: each owner onto the
// principal it owns, and each action onto the role that gives it on its own.
async function carryOverLines(client: PoolClient) {
  const old = await client.query(
    "SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='relations' AND column_name='id'",
  );
  if (!old.rowCount) return;
  await client.query(`
    ALTER TABLE principals ADD COLUMN owner_id uuid REFERENCES principals(id) ON DELETE RESTRICT CHECK (owner_id <> id);
    UPDATE principals p SET owner_id=r.subject_id FROM relations r WHERE r.principal_id=p.id AND r.relation='owner';
    ALTER TABLE relations RENAME TO relations_carried;
    CREATE TABLE relations (
      subject_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
      relation text NOT NULL CHECK (relation ~ '^[a-z][a-z_]*[a-z]$'),
      principal_id uuid REFERENCES principals(id) ON DELETE CASCADE,
      resource_id uuid REFERENCES resources(id) ON DELETE CASCADE,
      created_at timestamptz NOT NULL DEFAULT now(),
      CHECK ((principal_id IS NULL) <> (resource_id IS NULL)),
      CHECK (subject_id <> principal_id)
    );
    INSERT INTO relations(subject_id,relation,principal_id,created_at)
      SELECT subject_id,relation,principal_id,created_at FROM relations_carried WHERE relation IN ('agent','member','payer');
    CREATE TEMPORARY TABLE carried_roles(type text, action text, role text) ON COMMIT DROP;
    INSERT INTO carried_roles VALUES ('principal','read','reader'),('principal','create','creator'),('principal','update','editor'),('principal','share','sharer'),('principal','execute','runner'),('principal','credentials','credential_manager'),('principal','billing','billing_manager'),('principal','export','exporter'),('variable','read','reader'),('variable','update','editor'),('variable','share','sharer'),('variable','reveal','revealer'),('variable','use','user'),('connection','read','reader'),('connection','update','editor'),('connection','share','sharer'),('connection','reveal','revealer'),('connection','use','user'),('service','read','reader'),('service','update','editor'),('service','delete','deleter'),('service','share','sharer'),('service','transfer','transferrer'),('service','use','user'),('method','read','reader'),('method','update','editor'),('method','delete','deleter'),('method','share','sharer'),('method','transfer','transferrer'),('method','use','user'),('app','read','reader'),('app','update','editor'),('app','share','sharer'),('app','reveal','revealer'),('app','use','user'),('object','read','reader'),('object','update','editor'),('object','delete','deleter'),('object','share','sharer'),('object','transfer','transferrer'),('object','use','user'),('environment','read','reader'),('environment','update','editor'),('environment','delete','deleter'),('environment','share','sharer'),('environment','use','user'),('environment','execute','runner'),('function','read','reader'),('function','update','editor'),('function','delete','deleter'),('function','share','sharer'),('function','transfer','transferrer'),('function','execute','runner');
    INSERT INTO relations(subject_id,relation,resource_id,created_at)
      SELECT g.principal_id,m.role,g.resource_id,g.created_at FROM grants g JOIN resources r ON r.id=g.resource_id
      CROSS JOIN unnest(g.actions) a(action) JOIN carried_roles m ON m.type=r.kind AND m.action=a.action;
    INSERT INTO relations(subject_id,relation,principal_id)
      SELECT g.principal_id,m.role,g.target_id FROM principal_grants g
      CROSS JOIN unnest(g.actions) a(action) JOIN carried_roles m ON m.type='principal' AND m.action=a.action
      WHERE g.principal_id<>g.target_id;
    DROP TABLE relations_carried, grants, principal_grants;
  `);
}
