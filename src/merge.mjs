import { fail } from './errors.mjs';

// Two accounts of one person made one: everything one has - what it owns, the principals it owns, its passkeys and
// addresses - becomes the other's, and it ends. Decided by both: this one by its session, the other by a passkey of
// its answering; which of the two remains is chosen when completing. The lines the one that ends drew or was drawn
// end with it, as when any principal ends; what is owned keeps the lines onto it.
//
// In two steps, so that the browser can re-seal the other's secrets for this one's key with the other's key,
// which the passkey it answered with yields: begin verifies the passkey and says what there is; complete does it.
const TICKET_TTL = 5 * 60_000;

export class Merge {
  constructor(parts) { Object.assign(this, parts); }
  // The other account's passkeys are the ones that may answer; the one that does must be that account's.
  options(principalId, otherId, { origin }) {
    const other = this.principals.at(otherId).id;
    if (other === principalId) fail(400, 'invalid_merge', 'このアカウント自身とは統合できません。');
    const credentials = this.webauthn.list(other).map(row => row.id);
    if (!credentials.length) fail(409, 'no_passkey', '相手のアカウントにパスキーがありません。');
    return this.webauthn.authentication({ origin, purpose: 'merge', allowCredentials: credentials });
  }
  async begin(principalId, response, { origin, expected }) {
    const proven = await this.webauthn.authenticate(response, { origin, purpose: 'merge' });
    const other = proven.principalId;
    if (other === principalId) fail(400, 'invalid_merge', 'このパスキーはこのアカウントのものです。');
    if (expected !== undefined && other !== expected) fail(400, 'invalid_merge', 'このパスキーは指定したアカウントのものではありません。');
    if (this.environments.list(other).some(row => row.status !== 'stopped')) fail(409, 'environments_open', '相手のアカウントに開いている環境があります。先に閉じてください。');
    const ticket = this.challenges.issue('merge', principalId + ':' + other, { data: { credential: proven.credentialId }, ttl: TICKET_TTL });
    const secrets = this.secrets.list(other).map(row => ({ id: row.id, name: row.name, envelope: this.keys.envelopeOf(row.id, other)?.toString('base64url') ?? null }));
    return { ticket, other: this.principals.get(other), key: this.keys.view(other), wrap: this.keys.wrapOf(proven.credentialId), secrets };
  }
  // into: which remains - 'this' (the session's) or 'other' (the passkey's). envelopes: the ending one's secrets'
  // keys sealed for the remaining one, by id, as the browser made them. public_key and wrap: this principal's key when
  // it had none and remains, made with what the passkey yielded.
  complete(sessionId, { ticket, into = 'this', envelopes = {}, wrap, public_key } = {}) {
    const spent = this.challenges.take('merge', ticket);
    if (!spent || spent.subject.split(':')[0] !== sessionId) fail(400, 'invalid_merge', 'やり直してください。');
    if (!['this', 'other'].includes(into)) fail(400, 'invalid_merge', '残すアカウントを指定してください。');
    const answered = spent.subject.split(':')[1], credentialId = spent.data.credential;
    if (!this.principals.get(answered)) fail(404, 'not_found', '相手が見つかりません。');
    if (!envelopes || typeof envelopes !== 'object' || Array.isArray(envelopes)) fail(400, 'invalid_envelope', '封筒を確認してください。');
    const [principalId, other] = into === 'this' ? [sessionId, answered] : [answered, sessionId];
    return this.store.transaction(() => {
      if (into === 'this' && public_key !== undefined && !this.keys.publicKeyOf(principalId)) this.keys.publish(principalId, public_key);
      const moved = { secrets: 0, connections: 0, objects: 0, apps: 0, services: 0, principals: 0, webauthn_credentials: 0, emails: 0 };
      for (const row of this.secrets.list(other)) { this.secrets.transfer(row, principalId, envelopes[row.id]); moved.secrets++; }
      for (const row of this.connections.list(other)) { this.connections.transfer(row, principalId); moved.connections++; }
      for (const row of this.apps.list(other)) { this.apps.transfer(row, principalId); moved.apps++; }
      for (const row of this.services.list(other)) { this.services.transfer(row, principalId); moved.services++; }
      if (this.objects.enabled) for (const row of this.objects.list(other)) { this.objects.transfer(row, principalId); moved.objects++; }
      for (const row of this.principals.owned(other)) { if (row.id !== principalId) { this.principals.transfer(row.id, other, principalId); moved.principals++; } }
      moved.webauthn_credentials = this.db.prepare('UPDATE webauthn_credentials SET principal_id=? WHERE principal_id=?').run(principalId, other).changes;
      // The ending one's key is gone with it: its wraps go; the remaining one's wraps stay. The passkey that answered
      // wraps the remaining key when the browser could make that wrap.
      this.db.prepare('DELETE FROM key_wraps WHERE credential_id IN (SELECT id FROM webauthn_credentials WHERE principal_id=? AND user_handle=?)').run(principalId, other);
      if (wrap !== undefined) this.keys.keepWrap(credentialId, wrap);
      moved.emails = this.db.prepare('UPDATE emails SET principal_id=? WHERE principal_id=?').run(principalId, other).changes;
      this.requests.cancelFrom(other);
      this.resources.removeAll(other);
      this.principals.remove(other);
      this.auditLog.write(sessionId, 'principal.merged', 'principal', principalId, { from: other, ...moved });
      return { into: principalId, from: other, moved };
    });
  }
}
