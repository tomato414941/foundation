export async function cleanupIdentities(db, ids) {
  await db.transaction(async connection => {
    await connection.query('DELETE FROM principals WHERE id=ANY($1::uuid[]) OR owner_id=ANY($1::uuid[])', [ids]);
  });
}
