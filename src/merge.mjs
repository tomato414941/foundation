import { fail } from './errors.mjs';

// Two accounts of one person made one: everything the other has - what it owns, the principals it owns, its
// passkeys and addresses - becomes this one's, and the other ends. Decided by both: this one by its session, the
// other by a passkey of its answering. The lines the other drew or was drawn end with it, as when any principal
// ends; what is owned keeps the lines onto it.
//
// In two steps, so that the browser can re-seal the other's secrets for this one's key with the other's key,
// which the passkey it answered with yields: begin verifies the passkey and says what there is; complete does it.
const TICKET_TTL = 5 * 60_000;

export class Merge {
  constructor(parts) { Object.assign(this, parts); }
  async begin(principalId, response, { origin }) {
    const proven = await this.webauthn.authenticate(response, { origin, purpose: 'merge' });
    const other = proven.principalId;
    if (other === principalId) fail(400, 'invalid_merge', 'このパスキーはこのアカウントのものです。');
    if (this.environments.list(other).some(row => row.status !== 'stopped')) fail(409, 'environments_open', '相手のアカウントに開いている環境があります。先に閉じてください。');
    const ticket = this.challenges.issue('merge', principalId + ':' + other, { data: { credential: proven.credentialId }, ttl: TICKET_TTL });
    const secrets = this.secrets.list(other).map(row => ({ id: row.id, name: row.name, envelope: this.keys.envelopeOf(row.id, other)?.toString('base64url') ?? null }));
    return { ticket, from: this.principals.get(other), key: this.keys.view(other), wrap: this.keys.wrapOf(proven.credentialId), secrets };
  }
  // envelopes: the other's secrets' keys sealed for this principal, by id, as the browser made them. public_key and
  // wrap: this principal's key when it had none, made with what the passkey yielded.
  complete(principalId, { ticket, envelopes = {}, wrap, public_key } = {}) {
    const spent = this.challenges.take('merge', ticket);
    if (!spent || spent.subject.split(':')[0] !== principalId) fail(400, 'invalid_merge', 'やり直してください。');
    const other = spent.subject.split(':')[1], credentialId = spent.data.credential;
    if (!this.principals.get(other)) fail(404, 'not_found', '相手が見つかりません。');
    if (!envelopes || typeof envelopes !== 'object' || Array.isArray(envelopes)) fail(400, 'invalid_envelope', '封筒を確認してください。');
    return this.store.transaction(() => {
      if (public_key !== undefined && !this.keys.publicKeyOf(principalId)) this.keys.publish(principalId, public_key);
      const moved = { secrets: 0, connections: 0, objects: 0, apps: 0, services: 0, principals: 0, webauthn_credentials: 0, emails: 0 };
      for (const row of this.secrets.list(other)) { this.secrets.transfer(row, principalId, envelopes[row.id]); moved.secrets++; }
      for (const row of this.connections.list(other)) { this.connections.transfer(row, principalId); moved.connections++; }
      for (const row of this.apps.list(other)) { this.apps.transfer(row, principalId); moved.apps++; }
      for (const row of this.services.list(other)) { this.services.transfer(row, principalId); moved.services++; }
      if (this.objects.enabled) for (const row of this.objects.list(other)) { this.objects.transfer(row, principalId); moved.objects++; }
      for (const row of this.principals.owned(other)) { if (row.id !== principalId) { this.principals.transfer(row.id, other, principalId); moved.principals++; } }
      moved.webauthn_credentials = this.db.prepare('UPDATE webauthn_credentials SET principal_id=? WHERE principal_id=?').run(principalId, other).changes;
      this.db.prepare('DELETE FROM key_wraps WHERE credential_id IN (SELECT id FROM webauthn_credentials WHERE principal_id=?) AND credential_id<>?').run(principalId, credentialId);
      if (wrap !== undefined) this.keys.keepWrap(credentialId, wrap); else this.db.prepare('DELETE FROM key_wraps WHERE credential_id=?').run(credentialId);
      moved.emails = this.db.prepare('UPDATE emails SET principal_id=? WHERE principal_id=?').run(principalId, other).changes;
      this.requests.cancelFrom(other);
      this.resources.removeAll(other);
      this.principals.remove(other);
      this.auditLog.write(principalId, 'principal.merged', 'principal', principalId, { from: other, ...moved });
      return { from: other, moved };
    });
  }
}
