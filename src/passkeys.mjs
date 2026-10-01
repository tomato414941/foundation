import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { fail } from './errors.mjs';

// Passkeys: public keys principals prove themselves with, by WebAuthn. Whatever made the passkey - a browser, a
// security key, the CLI - registers and answers the same way, and is checked the same way. A challenge is one of
// Foundation's single-use values; answering it spends it.
const TTL = 5 * 60_000;
const NAME_MAX = 80;
const COLUMNS = 'id, principal_id, name, created_at, last_used_at';
const refused = () => fail(400, 'invalid_passkey', 'パスキーを確認できませんでした。もう一度お試しください。');
// The challenge a response answers, as the client signed it.
function answered(response) {
  try { return Buffer.from(JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url')).challenge, 'base64url').toString(); }
  catch { return undefined; }
}
const where = origin => ({ expectedOrigin: origin, expectedRPID: new URL(origin).hostname });

export class Passkeys {
  constructor(store, challenges) { Object.assign(this, { store, db: store.db, challenges }); }
  list(principalId) { return this.db.prepare(`SELECT ${COLUMNS} FROM passkeys WHERE principal_id=? ORDER BY created_at, id`).all(principalId); }
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} FROM passkeys WHERE id=?`).get(id) : undefined; }
  // A passkey taken away also ends the sessions it proved: the device it was on may be gone.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare("DELETE FROM sessions WHERE proof='passkey' AND proof_ref=?").run(row.id);
      this.db.prepare('DELETE FROM passkeys WHERE id=?').run(row.id);
    });
  }
  view(row) {
    const at = value => value === null ? null : new Date(value).toISOString();
    return { id: row.id, name: row.name, created_at: at(row.created_at), last_used_at: at(row.last_used_at) };
  }

  // Registering: the options a client makes a passkey from, for this principal, and then what it made.
  async registration(principalId, { origin, userName }) {
    const challenge = this.challenges.issue('passkey', 'register:' + principalId, { ttl: TTL });
    return generateRegistrationOptions({ rpName: 'Foundation', rpID: new URL(origin).hostname, userID: Buffer.from(principalId), userName, userDisplayName: userName,
      challenge, attestationType: 'none', excludeCredentials: this.list(principalId).map(row => ({ id: row.id })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' } });
  }
  async register(principalId, response, { origin, name }) {
    const label = typeof name === 'string' ? name.trim() : '';
    if (!label || label.length > NAME_MAX || /[\x00-\x1f\x7f]/.test(label)) fail(400, 'invalid_name', '名前は80文字までで指定してください。');
    const challenge = answered(response), spent = this.challenges.take('passkey', challenge);
    if (!spent || spent.subject !== 'register:' + principalId) refused();
    let verified;
    try { verified = await verifyRegistrationResponse({ response, expectedChallenge: Buffer.from(challenge).toString('base64url'), ...where(origin), requireUserVerification: false }); }
    catch { refused(); }
    if (!verified.verified) refused();
    const { credential, credentialBackedUp } = verified.registrationInfo;
    if (this.get(credential.id)) fail(409, 'passkey_exists', 'このパスキーはすでに登録されています。');
    this.db.prepare('INSERT INTO passkeys (id,principal_id,public_key,sign_count,name,created_at) VALUES (?,?,?,?,?,?)')
      .run(credential.id, principalId, Buffer.from(credential.publicKey), credential.counter, label, Date.now());
    return { passkey: this.get(credential.id), backedUp: credentialBackedUp };
  }

  // Signing in: any passkey may answer, and the one that does says whose it is.
  async authentication({ origin }) {
    const challenge = this.challenges.issue('passkey', 'signin', { ttl: TTL });
    return generateAuthenticationOptions({ rpID: new URL(origin).hostname, challenge, userVerification: 'preferred', allowCredentials: [] });
  }
  async authenticate(response, { origin }) {
    const challenge = answered(response), spent = this.challenges.take('passkey', challenge);
    const row = spent?.subject === 'signin' && typeof response?.id === 'string' ? this.db.prepare('SELECT * FROM passkeys WHERE id=?').get(response.id) : undefined;
    if (!row) fail(401, 'invalid_passkey', 'パスキーを確認できませんでした。');
    const handle = response.response?.userHandle;
    if (handle && Buffer.from(handle, 'base64url').toString() !== row.principal_id) fail(401, 'invalid_passkey', 'パスキーを確認できませんでした。');
    let verified;
    try {
      verified = await verifyAuthenticationResponse({ response, expectedChallenge: Buffer.from(challenge).toString('base64url'), ...where(origin), requireUserVerification: false,
        credential: { id: row.id, publicKey: new Uint8Array(row.public_key), counter: row.sign_count } });
    } catch { fail(401, 'invalid_passkey', 'パスキーを確認できませんでした。'); }
    if (!verified.verified) fail(401, 'invalid_passkey', 'パスキーを確認できませんでした。');
    this.db.prepare('UPDATE passkeys SET sign_count=?, last_used_at=? WHERE id=?').run(verified.authenticationInfo.newCounter, Date.now(), row.id);
    return { principalId: row.principal_id, passkeyId: row.id };
  }
}
