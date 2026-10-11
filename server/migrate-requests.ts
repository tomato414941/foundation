import type { Database } from './database.js';

export async function migrateRequests(db: Database) {
  await db.transaction(async connection => {
    await connection.query('SELECT pg_advisory_xact_lock(736023746)');
    if (await db.one("SELECT 1 FROM schema_migrations WHERE name='independent-request-delivery'", [], connection)) return;
    if (await db.one("SELECT to_regclass('approval_requests') AS name", [], connection).then(row => row?.name)) {
      await connection.query(`INSERT INTO requests(id,execution_id,from_id,to_id,message,purpose,state,expires_at,created_at)
        SELECT e.id,e.id,e.creator_id,e.responder_id,e.message,CASE WHEN e.proposal IS NULL THEN 'input' ELSE 'approval' END,
        CASE WHEN e.response='none' THEN 'accepted' ELSE e.response END,e.expires_at,e.created_at
        FROM executions e WHERE EXISTS(SELECT 1 FROM approval_requests r WHERE r.id=e.id)
        OR e.response='pending' AND (e.responder_id IS NOT NULL OR e.code_hash IS NOT NULL)
        ON CONFLICT(id) DO NOTHING`);
      const constraints = await db.all<{ conname: string }>(`SELECT conname FROM pg_constraint
        WHERE conrelid='request_links'::regclass AND contype='f' AND confrelid='approval_requests'::regclass`, [], connection);
      for (const { conname } of constraints) await connection.query('ALTER TABLE request_links DROP CONSTRAINT "' + conname.replaceAll('"', '""') + '"');
      await connection.query('ALTER TABLE request_links ADD CONSTRAINT request_links_delivery FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE');
      await connection.query('DROP TABLE approval_requests');
    }
    await connection.query("INSERT INTO schema_migrations(name) VALUES('independent-request-delivery')");
  });
}
