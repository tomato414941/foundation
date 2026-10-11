export async function cleanupIdentities(db, ids) {
  await db.transaction(async connection => {
    await connection.query('DELETE FROM function_invocations WHERE owner_id=ANY($1::uuid[]) OR function_owner_id=ANY($1::uuid[])', [ids]);
    await connection.query('DELETE FROM execution_tasks WHERE owner_id=ANY($1::uuid[])', [ids]);
    await connection.query('DELETE FROM principals WHERE owner_id=ANY($1::uuid[])', [ids]);
    await connection.query('DELETE FROM principals WHERE id=ANY($1::uuid[])', [ids]);
  });
}
