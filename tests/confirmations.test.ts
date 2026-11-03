import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture } from './support.js';
import { addPasskey, softwarePasskey } from './passkey-support.js';
import { rotateKeys } from './key-rotation-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import type { Mailer } from '../server/mail.js';
import { bindKeys, newIdentityKeys, publicPart, sign, signBinding } from '../shared/authority.js';
import type { IdentityKeys } from '../shared/authority.js';
import { decode, open, wrap } from '../shared/encryption.js';
import { decryptionContext, signConfirmation } from '../shared/confirmations.js';
import type { ConfirmationView } from '../shared/confirmations.js';

type Response = Awaited<ReturnType<Awaited<ReturnType<typeof setup>>['call']>>;
interface Holder { token: string; keys: IdentityKeys }

async function setup(mailer?: Mailer) {
  const f = await fixture();
  const context = await createContext(f.config, { db: f.db, mailer: mailer ?? f.mailer });
  const app = await buildApp(context);
  const call = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, token: string, payload?: object, confirmation?: string) =>
    app.inject({ method, url, headers: { authorization: 'Bearer ' + token, ...(confirmation ? { 'foundation-confirmation': confirmation } : {}) },
      ...(payload === undefined ? {} : { payload }) });
  // Starts a confirmation for the change a refused call named.
  async function start(token: string, refused: Response) {
    assert.equal(refused.json().error?.code, 'confirmation_required', refused.body);
    const started = await call('POST', '/api/confirmations', token, { operation: refused.json().error.details.operation });
    assert.equal(started.statusCode, 201, started.body);
    return started.json() as ConfirmationView;
  }
  // Confirms it by signing with the holder's keys.
  async function signed(holder: Holder, refused: Response) {
    const view = await start(holder.token, refused);
    const proved = await call('POST', '/api/confirmations/' + view.id + '/proof', holder.token,
      { method: 'signature', signature: await signConfirmation(view, holder.keys.signing) });
    assert.equal(proved.statusCode, 200, proved.body);
    return view.id;
  }
  // Confirms it with the code sent by email.
  async function emailed(token: string, refused: Response) {
    const view = await start(token, refused);
    const sent = await call('POST', '/api/confirmations/' + view.id + '/email', token, {});
    assert.equal(sent.statusCode, 200, sent.body);
    const proved = await call('POST', '/api/confirmations/' + view.id + '/proof', token, { method: 'email', code: f.mailer.codes.at(-1)!.code });
    assert.equal(proved.statusCode, 200, proved.body);
    return view.id;
  }
  async function email(principalId: string) {
    const id = randomUUID();
    await f.db.pool.query("INSERT INTO credentials(id,principal_id,kind,name,identifier) VALUES($1,$2,'email',$3,$3)",
      [id, principalId, 'person-' + id.slice(0, 8) + '@example.com']);
    return { id, session: (await f.authentication.session(principalId, id)).token };
  }
  async function close() { await app.close(); await f.close(); }
  return { f, context, app, call, start, signed, emailed, email, close };
}
const credentials = (principalId: string) => '/api/principals/' + principalId + '/credentials';

test('APIトークンだけではAPIキーを発行せず、署名で確認すると同じ発行をAPIから一度だけ完了する', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const refused = await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' });
  assert.equal(refused.statusCode, 403);
  assert.deepEqual(refused.json().error.details, { methods: ['signature'],
    operation: { action: 'credential.issue', principalId: person.actor.id, name: 'Laptop', expiresAt: null } });
  const confirmation = await s.signed(person, refused);
  const issued = await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' }, confirmation);
  assert.equal(issued.statusCode, 201, issued.body);
  const again = await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' }, confirmation);
  assert.equal(again.json().error.code, 'confirmation_invalid');
});

test('確認は操作内容・操作者・サインインに結び付き、別の変更や別のキー・別の主体、期限切れや改ざんでは使えない', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder'), other = await s.f.person('Other');
  const second = await s.f.authentication.issueKey(person.actor.id, 'Second');
  const refused = await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' });
  const confirmation = await s.signed(person, refused);
  const attempts = [
    await s.call('POST', credentials(person.actor.id), person.token, { name: 'Other name' }, confirmation),
    await s.call('POST', credentials(person.actor.id), second.token, { name: 'Laptop' }, confirmation),
    await s.call('POST', credentials(other.actor.id), other.token, { name: 'Laptop' }, confirmation),
  ];
  for (const attempt of attempts) assert.equal(attempt.json().error.code, 'confirmation_invalid', attempt.body);
  assert.equal((await s.call('GET', '/api/confirmations/' + confirmation, other.token)).statusCode, 404);
  await s.f.db.pool.query("UPDATE challenges SET expires_at=now()-interval '1 second' WHERE id=$1", [confirmation]);
  assert.equal((await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' }, confirmation)).json().error.code,
    'confirmation_invalid');
  const view = await s.start(person.token, refused);
  for (const signature of [await sign({ ...view.challenge, nonce: 'changed' }, person.keys.signing, 'operation-confirmation'),
    await signConfirmation(view, other.keys.signing)]) {
    const proved = await s.call('POST', '/api/confirmations/' + view.id + '/proof', person.token, { method: 'signature', signature });
    assert.equal(proved.json().error.code, 'invalid_proof');
  }
  assert.equal((await s.call('GET', '/api/confirmations/' + view.id, person.token)).json().state, 'pending');
});

test('自分のAPIキーは確認なしで手放し、他のAPIキーを消すには確認を求める', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const second = await s.f.authentication.issueKey(person.actor.id, 'Second');
  const refused = await s.call('DELETE', credentials(person.actor.id) + '/' + second.credential.id, person.token);
  assert.equal(refused.statusCode, 403);
  assert.equal((await s.call('DELETE', credentials(person.actor.id) + '/' + second.credential.id, person.token, undefined,
    await s.signed(person, refused))).statusCode, 200);
  const third = await s.f.authentication.issueKey(person.actor.id, 'Third');
  assert.equal((await s.call('DELETE', credentials(person.actor.id) + '/' + third.credential.id, third.token)).statusCode, 200);
});

test('盗まれたセッションと鍵では別のAPIキーを作れても、そのセッションのメールは署名では消せず、メールの確認を求める', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder'), mail = await s.email(person.actor.id);
  await s.f.authentication.issueKey(person.actor.id, 'Remaining');
  const stolen = { token: mail.session, keys: person.keys };
  const refused = await s.call('POST', credentials(person.actor.id), stolen.token, { name: 'Backdoor' });
  assert.deepEqual(refused.json().error.details.methods, ['signature', 'email']);
  assert.equal((await s.call('POST', credentials(person.actor.id), stolen.token, { name: 'Backdoor' }, await s.signed(stolen, refused))).statusCode, 201);
  const removal = await s.call('DELETE', credentials(person.actor.id) + '/' + mail.id, stolen.token);
  assert.equal(removal.statusCode, 403);
  assert.deepEqual(removal.json().error.details.methods, ['email']);
  const view = await s.start(stolen.token, removal);
  const signed = await s.call('POST', '/api/confirmations/' + view.id + '/proof', stolen.token,
    { method: 'signature', signature: await signConfirmation(view, person.keys.signing) });
  assert.equal(signed.json().error.code, 'method_unavailable');
  assert.ok(await s.f.db.one('SELECT 1 FROM credentials WHERE id=$1', [mail.id]));
  const confirmation = await s.emailed(stolen.token, removal);
  assert.equal((await s.call('DELETE', credentials(person.actor.id) + '/' + mail.id, stolen.token, undefined, confirmation)).statusCode, 200);
});

test('メールを送れない設定でも、メールを持つ主体のメール削除を署名で代えず、確認できないと伝える', async t => {
  const disabled: Mailer = { enabled: false, async send() { throw new Error('disabled'); }, async sendCode() { throw new Error('disabled'); } };
  const s = await setup(disabled); t.after(s.close);
  const person = await s.f.person('Holder'), mail = await s.email(person.actor.id);
  const removal = await s.call('DELETE', credentials(person.actor.id) + '/' + mail.id, person.token);
  assert.equal(removal.statusCode, 409);
  assert.equal(removal.json().error.code, 'confirmation_unavailable');
  assert.deepEqual(removal.json().error.details.methods, []);
  const refused = await s.call('POST', credentials(person.actor.id), person.token, { name: 'Laptop' });
  assert.deepEqual(refused.json().error.details.methods, ['signature']);
});

test('パスキーが持つ包みは署名だけでは置き換えずパスキーで確認し、包みのないパスキーには署名で初めて包む', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const holding = await addPasskey(s.f.db, person.actor.id, s.f.config.origin, 'previous'),
    empty = await addPasskey(s.f.db, person.actor.id, s.f.config.origin);
  const body = { wrappedKey: await wrap(person.keys, crypto.getRandomValues(new Uint8Array(32)), person.actor.id),
    publicKey: publicPart(person.keys.encryption) };
  const replace = await s.call('PUT', credentials(person.actor.id) + '/' + holding.id + '/wrap', person.token, body);
  assert.deepEqual(replace.json().error.details.methods, ['passkey']);
  const view = await s.start(person.token, replace);
  assert.equal((await s.call('POST', '/api/confirmations/' + view.id + '/proof', person.token,
    { method: 'signature', signature: await signConfirmation(view, person.keys.signing) })).json().error.code, 'method_unavailable');
  const { options } = (await s.call('POST', '/api/confirmations/' + view.id + '/passkey', person.token, {})).json();
  const proved = await s.call('POST', '/api/confirmations/' + view.id + '/proof', person.token, { method: 'passkey', credential: holding.assert(options) });
  assert.equal(proved.statusCode, 200, proved.body);
  assert.equal((await s.call('PUT', credentials(person.actor.id) + '/' + holding.id + '/wrap', person.token, body, view.id)).statusCode, 200);
  const first = await s.call('PUT', credentials(person.actor.id) + '/' + empty.id + '/wrap', person.token, body);
  assert.deepEqual(first.json().error.details.methods, ['signature', 'passkey']);
  assert.equal((await s.call('PUT', credentials(person.actor.id) + '/' + empty.id + '/wrap', person.token, body,
    await s.signed(person, first))).statusCode, 200);
});

test('盗んだトークンで管理権限の線を自分の主体へ引くには確認を求め、実行定義を経ても同じ確認を求める', async t => {
  const s = await setup(); t.after(s.close);
  const victim = await s.f.person('Victim'), attacker = await s.f.person('Attacker');
  for (const relation of ['credential_manager', 'member']) {
    const line = { subjectId: attacker.actor.id, relation, objectId: victim.actor.id };
    const refusals = [
      await s.call('POST', '/api/relations', victim.token, line),
      await s.call('POST', '/api/executions', victim.token, { operations: [{ name: 'relation.draw', input: line }] }),
      await s.call('POST', '/api/definitions/relation.draw/executions', victim.token, line),
    ];
    for (const refused of refusals) assert.equal(refused.json().error?.code, 'confirmation_required', refused.body);
    assert.equal((await s.call('GET', credentials(victim.actor.id), attacker.token)).statusCode, 403);
  }
  assert.equal(await s.f.db.one("SELECT 1 FROM executions WHERE creator_id=$1 AND state='failed'", [victim.actor.id]), undefined);
  const line = { subjectId: attacker.actor.id, relation: 'credential_manager', objectId: victim.actor.id };
  const refused = await s.call('POST', '/api/relations', victim.token, line);
  assert.equal((await s.call('POST', '/api/relations', victim.token, line, await s.signed(victim, refused))).statusCode, 200);
  assert.equal((await s.call('GET', credentials(victim.actor.id), attacker.token)).statusCode, 200);
  const delegated = await s.call('POST', '/api/relations', victim.token, { subjectId: attacker.actor.id, relation: 'delegate', objectId: victim.actor.id });
  assert.equal(delegated.statusCode, 200, delegated.body);
});

test('所有者は対象の秘密鍵なしに自分の確認で所有する主体のキーを発行し、主体の譲渡は相手の同意まで確認を保つ', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner'), next = await s.f.person('Next owner');
  const created = await s.call('POST', '/api/principals/' + owner.actor.id + '/principals', owner.token, { name: 'Agent' });
  assert.equal(created.statusCode, 201, created.body);
  const agent = created.json().id as string;
  const refused = await s.call('POST', credentials(agent), owner.token, { name: 'Agent key' });
  assert.deepEqual(refused.json().error.details.methods, ['signature']);
  assert.equal((await s.call('POST', credentials(agent), owner.token, { name: 'Agent key' }, await s.signed(owner, refused))).statusCode, 201);
  const transfer = await s.call('POST', '/api/principals/' + agent + '/transfer', owner.token, { to: next.actor.id });
  assert.equal(transfer.statusCode, 403);
  const confirmation = await s.signed(owner, transfer);
  const proposed = await s.call('POST', '/api/principals/' + agent + '/transfer', owner.token, { to: next.actor.id }, confirmation);
  assert.equal(proposed.statusCode, 202, proposed.body);
  assert.equal((await s.call('GET', '/api/confirmations/' + confirmation, owner.token)).json().state, 'held');
  const answered = await s.call('POST', '/api/executions/' + proposed.json().id + '/respond', next.token, {});
  assert.equal(answered.statusCode, 200, answered.body);
  assert.equal((await s.f.principals.get(agent)).owner_id, next.actor.id);
  assert.equal(await s.f.db.one('SELECT 1 FROM challenges WHERE id=$1', [confirmation]), undefined);
});

test('確認後に鍵が替わると確認を使えず、確認後に失敗した変更は確認を残す', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  // Keys wrapped for a public key the principal does not have fail after the confirmation is checked.
  const body = { name: 'Laptop', wrap: { wrappedKey: await wrap(person.keys, crypto.getRandomValues(new Uint8Array(32)), person.actor.id),
    publicKey: publicPart((await newIdentityKeys()).encryption) } };
  const refused = await s.call('POST', credentials(person.actor.id), person.token, body);
  const confirmation = await s.signed(person, refused);
  const failed = await s.call('POST', credentials(person.actor.id), person.token, body, confirmation);
  assert.equal(failed.json().error.code, 'encryption_key_changed', failed.body);
  assert.equal((await s.call('GET', '/api/confirmations/' + confirmation, person.token)).json().state, 'confirmed');
  await rotateKeys(s.context.keyRotations, person);
  assert.equal((await s.call('POST', credentials(person.actor.id), person.token, body, confirmation)).json().error.code,
    'confirmation_invalid');
});

test('取り消し中のAPIキーは、確認済みでも取り消しと競合した発行を完了しない', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const second = await s.f.authentication.issueKey(person.actor.id, 'Leaked');
  const leaked = { token: second.token, keys: person.keys };
  const refused = await s.call('POST', credentials(person.actor.id), leaked.token, { name: 'Backdoor' });
  const confirmation = await s.signed(leaked, refused);
  const revoking = await s.f.db.pool.connect();
  try {
    await revoking.query('BEGIN');
    await revoking.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [person.actor.id]);
    const issuing = s.call('POST', credentials(person.actor.id), leaked.token, { name: 'Backdoor' }, confirmation);
    await delay(300);
    await revoking.query('DELETE FROM credentials WHERE id=$1', [second.credential.id]);
    await revoking.query('COMMIT');
    const issued = await issuing;
    assert.ok([401, 403].includes(issued.statusCode), issued.body);
  } finally { revoking.release(); }
  assert.equal(await s.f.db.one("SELECT 1 FROM credentials WHERE principal_id=$1 AND name='Backdoor'", [person.actor.id]), undefined);
});

test('メールアドレスの追加はトークンだけでは受け付けず、確認するとリンクを送る', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const added = await s.call('POST', '/api/auth/email', person.token, { email: 'added@example.com', principalId: person.actor.id });
  assert.equal(added.json().error?.code, 'confirmation_required', added.body);
  assert.equal(s.f.mailer.sent.length, 0);
  const confirmation = await s.signed(person, added);
  assert.equal((await s.call('POST', '/api/auth/email', person.token, { email: 'added@example.com', principalId: person.actor.id },
    confirmation)).statusCode, 200);
  assert.equal(s.f.mailer.sent.at(-1)?.address, 'added@example.com');
});

test('同じメールから作った別のセッションでは、確認を使い回せない', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder'), mail = await s.email(person.actor.id);
  const other = (await s.f.authentication.session(person.actor.id, mail.id)).token;
  const refused = await s.call('POST', credentials(person.actor.id), mail.session, { name: 'Laptop' });
  const confirmation = await s.emailed(mail.session, refused);
  assert.equal((await s.call('GET', '/api/confirmations/' + confirmation, other)).statusCode, 404);
  assert.equal((await s.call('POST', credentials(person.actor.id), other, { name: 'Laptop' }, confirmation)).json().error.code,
    'confirmation_invalid');
  assert.equal((await s.call('POST', credentials(person.actor.id), mail.session, { name: 'Laptop' }, confirmation)).statusCode, 201);
});

test('暗号鍵だけを持つ未束縛の主体は、トークンだけでは他人の署名鍵を束縛せず、暗号鍵で封じた値を開くと自分の鍵を束縛する', async t => {
  const s = await setup(); t.after(s.close);
  const keys = await newIdentityKeys(), attacker = await newIdentityKeys();
  const legacy = await s.f.principals.create('Legacy', publicPart(keys.encryption));
  const { token } = await s.f.authentication.issueKey(legacy.id, 'Legacy key');
  const path = '/api/principals/' + legacy.id + '/binding';
  const forged = { ...bindKeys(legacy.id, keys), signing: publicPart(attacker.signing) };
  const stolen = await s.call('PUT', path, token, { binding: forged, signature: await sign(forged, attacker.signing, 'key-binding') });
  assert.equal(stolen.statusCode, 403);
  assert.deepEqual(stolen.json().error.details.methods, ['decryption']);
  const guessed = await s.start(token, stolen);
  assert.ok(guessed.sealed);
  assert.equal((await s.call('POST', '/api/confirmations/' + guessed.id + '/proof', token, { method: 'decryption', secret: 'guessed' }))
    .json().error.code, 'invalid_proof');
  await assert.rejects(s.f.bindings.current(legacy.id), { code: 'key_binding_required' });
  const own = await signBinding(bindKeys(legacy.id, keys), keys);
  const refused = await s.call('PUT', path, token, own);
  const view = await s.start(token, refused);
  const secret = decode(await open(view.sealed!, keys.encryption, view.id, decryptionContext(view.id)));
  assert.equal((await s.call('POST', '/api/confirmations/' + view.id + '/proof', token, { method: 'decryption', secret })).statusCode, 200);
  assert.equal((await s.call('PUT', path, token, own, view.id)).statusCode, 200);
  assert.deepEqual((await s.f.bindings.current(legacy.id)).binding, own.binding);
});

test('鍵も確認手段もない主体はトークンだけでは鍵を束縛せず、所有者が自分の確認で束縛する', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const agent = await s.f.principals.create('Agent', null, owner.actor.id);
  const { token } = await s.f.authentication.issueKey(agent.id, 'Agent key');
  const keys = await newIdentityKeys(), binding = await signBinding(bindKeys(agent.id, keys), keys);
  const path = '/api/principals/' + agent.id + '/binding';
  const alone = await s.call('PUT', path, token, binding);
  assert.equal(alone.statusCode, 409);
  assert.equal(alone.json().error.code, 'confirmation_unavailable');
  const refused = await s.call('PUT', path, owner.token, binding);
  assert.equal((await s.call('PUT', path, owner.token, binding, await s.signed(owner, refused))).statusCode, 200);
});

test('パスキーの追加は確認した登録応答のパスキーにだけ使え、同じ登録への別の応答に差し替えると受け付けない', async t => {
  const s = await setup(); t.after(s.close);
  const person = await s.f.person('Holder');
  const started = await s.call('POST', '/api/auth/passkeys/options', person.token,
    { intent: 'register', name: 'Added passkey', principalId: person.actor.id });
  assert.equal(started.statusCode, 200, started.body);
  const { challengeId, options } = started.json();
  const confirmed = softwarePasskey(s.f.config.origin), other = softwarePasskey(s.f.config.origin);
  const verify = (passkey: ReturnType<typeof softwarePasskey>, confirmation?: string) => s.call('POST', '/api/auth/passkeys/verify',
    person.token, { challengeId, credential: passkey.register(options) }, confirmation);
  const refused = await verify(confirmed);
  assert.equal(refused.json().error.details.operation.passkey.id, confirmed.identifier);
  const confirmation = await s.signed(person, refused);
  assert.equal((await verify(other, confirmation)).json().error.code, 'confirmation_invalid');
  assert.equal((await verify(confirmed, confirmation)).statusCode, 200);
  assert.deepEqual((await s.f.db.all<{ identifier: string }>("SELECT identifier FROM credentials WHERE principal_id=$1 AND kind='passkey'",
    [person.actor.id])).map(row => row.identifier), [confirmed.identifier]);
});
