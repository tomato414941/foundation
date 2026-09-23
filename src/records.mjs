import { held, names, delivery } from './held.mjs';

// The seam between acquisition and storage.
//
// Acquisition (an adapter and its client) knows a service: how to obtain a value, how to check it, how to
// refresh it, and under which names a command expects it. Storage knows none of that. So the translation
// happens once, here, at the moment the value is acquired: the adapter's own shape goes into `renewal`,
// which only that adapter reads again, and everything storage and delivery need is written out plainly
// beside it. From then on, handing the value to a command never consults an adapter, and a value that no
// adapter ever touched is delivered by exactly the same path.
export class Records {
  constructor(store, adapters) { this.store = store; this.adapters = adapters; }
  // Turns what a client returned into what storage holds.
  build(adapterId, secret, credential) {
    const adapter = this.adapters.get(adapterId);
    const { environment = {}, files = [], expo_session = null } = adapter.deliver(secret, credential) || {};
    const declared = new Set(this.adapters.delivered(adapterId, secret));
    for (const name of [...Object.keys(environment), ...files.map(file => file.env)]) {
      if (!declared.has(name)) throw new Error('Adapter ' + adapterId + ' delivered an undeclared variable: ' + name);
    }
    return held({ environment, files, session: expo_session, facts: adapter.client.facts?.(secret) || {}, renewal: secret,
      expires_at: secret.expires_at ?? null, expiry_known: secret.expiry_known ?? true,
      credential_type: secret.credential_type ?? adapter.credentialType ?? 'oauth2_access_token',
      scopes: secret.scopes, verification: secret.verification });
  }
  names(record) { return names(record); }
  delivery(record) { return delivery(record); }
  record(credential) { return this.store.secret(credential); }
  // The view a client is given in place of the store. It sees only its own shape, and every write it makes
  // is rebuilt into a record before storage accepts it.
  clientStore(adapterId) {
    const records = this;
    return {
      secret: credential => records.store.secret(credential).renewal,
      saveSecret(credential, secret) {
        const record = records.build(adapterId, secret, credential);
        records.store.saveSecret(credential, record, names(record));
      },
      reconnectRequired: credential => records.store.reconnectRequired(credential),
      transaction: fn => records.store.transaction(fn),
    };
  }
}
