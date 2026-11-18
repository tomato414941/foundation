import test from 'node:test';
import assert from 'node:assert/strict';
import { enroll, fixture } from './support.js';
import { createContext } from '../server/context.js';

test('空のDBでは起動せず、移行コマンドで準備したDBで起動し、移行し直してもアカウントを保つ', async t => {
  const f = await fixture(); t.after(f.close);
  const schema = (await f.db.one<{ schema: string }>('SELECT current_schema() AS schema'))!.schema;
  await f.db.pool.query(`DROP SCHEMA "${schema}" CASCADE`);
  await f.db.pool.query(`CREATE SCHEMA "${schema}"`);
  await assert.rejects(createContext(f.config, { db: f.db, mailer: f.mailer }), /npm run migrate/);
  const prepared = await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const person = await enroll(prepared.authentication, 'Retained account');
  await createContext(f.config, { db: f.db, mailer: f.mailer }, { migrate: true });
  const restarted = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const actor = (await restarted.authentication.authenticate(person.token))!;
  assert.equal((await restarted.principals.get(actor.id)).name, 'Retained account');
});

test('Foundationの移行で準備していない使用中のDBは移行を断る', async t => {
  const f = await fixture(); t.after(f.close);
  await f.db.pool.query('DROP TABLE schema_migrations');
  await assert.rejects(f.db.migrate(), /not prepared by Foundation migrations/);
});
