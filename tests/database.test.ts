import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { SchemaMigration } from '../server/database.js';

test('移行コマンドで既存のアカウントを保持してDBを準備し、準備済みのDBで起動する', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await f.person('Retained account');
  await f.db.pool.query('DELETE FROM schema_migrations WHERE name=$1', [SchemaMigration]);
  await assert.rejects(createContext(f.config, { db: f.db, mailer: f.mailer }), /npm run migrate/);
  await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const restarted = await createContext(f.config, { db: f.db, mailer: f.mailer });
  assert.equal((await restarted.authentication.authenticate(person.token))!.id, person.actor.id);
  assert.equal((await restarted.principals.get(person.actor.id)).name, 'Retained account');
});
