import { readFile } from 'node:fs/promises';
import pg from 'pg';
import type { PoolClient, QueryResultRow } from 'pg';

export type Queryable = Pick<pg.Pool, 'query'>;
export const SchemaMigration = '001-foundation-schema';
const RequiredMigrations = [SchemaMigration, '002-ssh-environments', '005-ownership', '008-key-rotations', '009-ssh-access', '010-output-names', '011-run-output-names', '012-remove-environments', '013-remove-http-settings', '014-seal-format', '015-requests-and-operations'];
// The migrations written in SQL alone, applied in order.
const SqlMigrations = ['002-ssh-environments', '005-ownership', '008-key-rotations', '009-ssh-access',
  '010-output-names', '011-run-output-names', '013-remove-http-settings', '014-seal-format'];
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
      // An empty database starts from the current schema; one in use goes on from the migrations it has applied.
      if (!installed?.migrations || !await this.one('SELECT 1 FROM schema_migrations WHERE name=$1', [SchemaMigration], client)) {
        if (installed?.principals) throw new Error('This database was not prepared by Foundation migrations.');
        await client.query(await readFile(new URL('./schema.sql', import.meta.url), 'utf8'));
        for (const name of RequiredMigrations) await client.query('INSERT INTO schema_migrations(name) VALUES($1) ON CONFLICT DO NOTHING', [name]);
      }
      for (const name of SqlMigrations)
        if (!await this.one('SELECT 1 FROM schema_migrations WHERE name=$1', [name], client)) {
          await client.query(await readFile(new URL(`./migrations/${name}.sql`, import.meta.url), 'utf8'));
          await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name]);
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
