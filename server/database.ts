import { readFile } from 'node:fs/promises';
import pg from 'pg';
import type { PoolClient, QueryResultRow } from 'pg';

export type Queryable = Pick<pg.Pool, 'query'>;
export class Database {
  readonly pool: pg.Pool;
  constructor(url: string, options: { max?: number; schema?: string } = {}) {
    if (options.schema && !/^[a-z][a-z0-9_]*$/.test(options.schema)) throw new Error('Invalid database schema');
    this.pool = new pg.Pool({ connectionString: url, max: options.max ?? 12, connectionTimeoutMillis: 10_000, idleTimeoutMillis: 30_000,
      options: `-c statement_timeout=30000${options.schema ? ' -c search_path=' + options.schema : ''}` });
  }
  async initialize() {
    const schema = await readFile(new URL('./schema.sql', import.meta.url), 'utf8');
    await this.transaction(async client => {
      await client.query('SELECT pg_advisory_xact_lock(736023741)');
      await client.query(schema);
    });
  }
  async all<T extends QueryResultRow>(sql: string, values: unknown[] = [], connection: Queryable = this.pool): Promise<T[]> {
    return (await connection.query<T>(sql, values)).rows;
  }
  async one<T extends QueryResultRow>(sql: string, values: unknown[] = [], connection: Queryable = this.pool): Promise<T | undefined> {
    return (await this.all<T>(sql, values, connection))[0];
  }
  async transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
  async close() { await this.pool.end(); }
}
export const iso = (value: Date | string) => value instanceof Date ? value.toISOString() : new Date(value).toISOString();
