export async function cleanupIdentities(db, ids) {
  await db.transaction(async connection => {
    await connection.query('DELETE FROM function_invocations WHERE owner_id=ANY($1::uuid[]) OR function_owner_id=ANY($1::uuid[])', [ids]);
    await connection.query('DELETE FROM execution_tasks WHERE owner_id=ANY($1::uuid[])', [ids]);
    await connection.query('DELETE FROM environment_processes WHERE owner_id IN (SELECT id FROM principals WHERE id=ANY($1::uuid[]) OR owner_id=ANY($1::uuid[]))', [ids]);
    await connection.query('DELETE FROM principals WHERE id=ANY($1::uuid[]) OR owner_id=ANY($1::uuid[])', [ids]);
  });
}
