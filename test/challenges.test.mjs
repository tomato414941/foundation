import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/store.mjs';
import { Challenges, PENDING_MAX } from '../src/challenges.mjs';
import { KEY } from './helpers.mjs';

test('確認値がいっぱいになると同じ用途のいちばん古いものから場所を譲り、新しく頼んだ人は断られない', t => {
  const store = new Store(':memory:', KEY); t.after(() => store.close());
  let at = 1_000_000;
  const challenges = new Challenges(store, { now: () => at });
  const link = challenges.issue('email', 'waiting@example.test', { ttl: 900_000 });
  const first = challenges.issue('webauthn', 'signin', { ttl: 300_000 });
  for (let n = 1; n < PENDING_MAX; n++) { at += 1; challenges.issue('webauthn', 'signin', { ttl: 300_000 }); }
  at += 1;
  const newest = challenges.issue('webauthn', 'signin', { ttl: 300_000 });
  assert.equal(store.db.prepare("SELECT count(*) n FROM challenges WHERE purpose='webauthn'").get().n, PENDING_MAX);
  assert.equal(challenges.take('webauthn', first), undefined, 'the oldest gave way');
  assert.equal(challenges.take('webauthn', newest).subject, 'signin', 'the one just asked for is answered');
  assert.equal(challenges.take('email', link).subject, 'waiting@example.test', 'another purpose is not touched');
  // What has expired is cleared when the next is issued.
  at += 300_001;
  challenges.issue('webauthn', 'signin', { ttl: 300_000 });
  assert.equal(store.db.prepare("SELECT count(*) n FROM challenges WHERE purpose='webauthn'").get().n, 1);
});
