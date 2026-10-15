import { readFile } from 'node:fs/promises';
import pg from 'pg';
import type { PoolClient, QueryResultRow } from 'pg';

export type Queryable = Pick<pg.Pool, 'query'>;
export const SchemaMigration = '001-foundation-schema';
const RequiredMigrations = [SchemaMigration, 'independent-operation-executions', 'independent-request-delivery', 'unified-execution-history', 'historical-server-runs', '002-ssh-environments', '003-files', '004-storage'];
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
  async migrate() {
    await this.transaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(736023741)');
      const installed = await this.one<{ principals: string | null; migrations: string | null }>(
        "SELECT to_regclass('principals') AS principals,to_regclass('schema_migrations') AS migrations", [], client);
      if (!installed?.migrations || !await this.one('SELECT 1 FROM schema_migrations WHERE name=$1', [SchemaMigration], client)) {
        const schema = await readFile(new URL(installed?.principals ? './migrations/001-foundation.sql' : './schema.sql', import.meta.url), 'utf8');
        await client.query(schema);
        const names = installed?.principals ? [SchemaMigration] : RequiredMigrations;
        for (const name of names) await client.query('INSERT INTO schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING', [name]);
      }
      if (!await this.one('SELECT 1 FROM schema_migrations WHERE name=$1', ['002-ssh-environments'], client)) {
        await client.query(await readFile(new URL('./migrations/002-ssh-environments.sql', import.meta.url), 'utf8'));
        await client.query('INSERT INTO schema_migrations(name) VALUES($1)', ['002-ssh-environments']);
      }
    });
  }
  async assertReady() {
    const installed = await this.one<{ migrations: string | null }>("SELECT to_regclass('schema_migrations') AS migrations");
    const applied = installed?.migrations ? await this.all<{ name: string }>('SELECT name FROM schema_migrations') : [];
    if (RequiredMigrations.some(name => !applied.some(row => row.name === name)))
      throw new Error('Apply database migrations with npm run migrate before starting Foundation.');
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
