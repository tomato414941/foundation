import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { fail } from './errors.mjs';

// WebAuthn credentials: public keys principals prove themselves with. Whatever made one - a browser or a password
// manager (a passkey), a security key, the CLI - registers and answers the same way, and is checked the same way. A
// row is what the specification calls a credential record. A challenge is one of
// Foundation's single-use values; answering it spends it.
const TTL = 5 * 60_000;
const NAME_MAX = 80;
const COLUMNS = 'id, principal_id, name, created_at, last_used_at';
const refused = () => fail(400, 'invalid_webauthn_credential', 'パスキーを確認できませんでした。もう一度お試しください。');
// The challenge a response answers, as the client signed it.
function answered(response) {
  try { return Buffer.from(JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url')).challenge, 'base64url').toString(); }
  catch { return undefined; }
}
const where = origin => ({ expectedOrigin: origin, expectedRPID: new URL(origin).hostname });

export class WebauthnCredentials {
  constructor(store, challenges) { Object.assign(this, { store, db: store.db, challenges }); }
  list(principalId) { return this.db.prepare(`SELECT ${COLUMNS} FROM webauthn_credentials WHERE principal_id=? ORDER BY created_at, id`).all(principalId); }
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} FROM webauthn_credentials WHERE id=?`).get(id) : undefined; }
  // A credential taken away also ends the sessions it proved: the device it was on may be gone.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare("DELETE FROM sessions WHERE proof='webauthn' AND proof_ref=?").run(row.id);
      this.db.prepare('DELETE FROM webauthn_credentials WHERE id=?').run(row.id);
    });
  }
  view(row) {
    const at = value => value === null ? null : new Date(value).toISOString();
    return { id: row.id, name: row.name, created_at: at(row.created_at), last_used_at: at(row.last_used_at) };
  }

  // Registering: the options a client makes a credential from - for a principal, or for one that registering it
  // makes - and then what it made.
  async registration(principalId, { origin, userName, creating = false }) {
    const challenge = this.challenges.issue('webauthn', (creating ? 'create:' : 'register:') + principalId, { ttl: TTL });
    return generateRegistrationOptions({ rpName: 'Foundation', rpID: new URL(origin).hostname, userID: Buffer.from(principalId), userName, userDisplayName: userName,
      challenge, attestationType: 'none', excludeCredentials: creating ? [] : this.list(principalId).map(row => ({ id: row.id })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' } });
  }
  // For a principal that is (principalId), or - given make - for the one the options were made for, which make(id)
  // brings into being in the same transaction.
  async register(response, { origin, name, principalId, make }) {
    const label = typeof name === 'string' ? name.trim() : '';
    if (!label || label.length > NAME_MAX || /[\x00-\x1f\x7f]/.test(label)) fail(400, 'invalid_name', '名前は80文字までで指定してください。');
    const challenge = answered(response), spent = this.challenges.take('webauthn', challenge);
    const at = spent ? spent.subject.indexOf(':') : -1, purpose = spent?.subject.slice(0, at), owner = spent?.subject.slice(at + 1);
    if (!spent || (make ? purpose !== 'create' : purpose !== 'register' || owner !== principalId)) refused();
    let verified;
    try { verified = await verifyRegistrationResponse({ response, expectedChallenge: Buffer.from(challenge).toString('base64url'), ...where(origin), requireUserVerification: false }); }
    catch { refused(); }
    if (!verified.verified) refused();
    const { credential, credentialBackedUp } = verified.registrationInfo;
    this.store.transaction(() => {
      if (this.get(credential.id)) fail(409, 'webauthn_credential_exists', 'このパスキーはすでに登録されています。');
      make?.(owner);
      this.db.prepare('INSERT INTO webauthn_credentials (id,principal_id,public_key,sign_count,name,created_at) VALUES (?,?,?,?,?,?)')
        .run(credential.id, owner, Buffer.from(credential.publicKey), credential.counter, label, Date.now());
    });
    return { principalId: owner, credential: this.get(credential.id), backedUp: credentialBackedUp };
  }

  // Signing in: any credential may answer, and the one that does says whose it is.
  async authentication({ origin }) {
    const challenge = this.challenges.issue('webauthn', 'signin', { ttl: TTL });
    return generateAuthenticationOptions({ rpID: new URL(origin).hostname, challenge, userVerification: 'preferred', allowCredentials: [] });
  }
  async authenticate(response, { origin }) {
    const challenge = answered(response), spent = this.challenges.take('webauthn', challenge);
    const row = spent?.subject === 'signin' && typeof response?.id === 'string' ? this.db.prepare('SELECT * FROM webauthn_credentials WHERE id=?').get(response.id) : undefined;
    if (!row) fail(401, 'invalid_webauthn_credential', 'パスキーを確認できませんでした。');
    const handle = response.response?.userHandle;
    if (handle && Buffer.from(handle, 'base64url').toString() !== row.principal_id) fail(401, 'invalid_webauthn_credential', 'パスキーを確認できませんでした。');
    let verified;
    try {
      verified = await verifyAuthenticationResponse({ response, expectedChallenge: Buffer.from(challenge).toString('base64url'), ...where(origin), requireUserVerification: false,
        credential: { id: row.id, publicKey: new Uint8Array(row.public_key), counter: row.sign_count } });
    } catch { fail(401, 'invalid_webauthn_credential', 'パスキーを確認できませんでした。'); }
    if (!verified.verified) fail(401, 'invalid_webauthn_credential', 'パスキーを確認できませんでした。');
    this.db.prepare('UPDATE webauthn_credentials SET sign_count=?, last_used_at=? WHERE id=?').run(verified.authenticationInfo.newCounter, Date.now(), row.id);
    return { principalId: row.principal_id, credentialId: row.id };
  }
}
