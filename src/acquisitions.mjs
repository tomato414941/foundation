import { fail } from './errors.mjs';
import { secretPath, VALUE_MAX } from './secrets.mjs';

// The seam between an acquisition and the store.
//
// An adapter knows a service: how to obtain a value, how to check it, how to refresh it, and the names a
// command expects it under. The store knows none of that. So the translation happens once, here, the moment
// something is obtained: what the adapter returned goes into the acquisition's own state, which only that
// adapter reads again, and what it produced is written as ordinary entries under its prefix.
//
// From then on nothing is special about them. They are listed, delivered and shown exactly like anything
// else kept, and the only difference is that Foundation keeps these current and can revoke them.
const slug = value => String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
// The last segment is the variable itself, so a path says exactly what it becomes, and one value delivered
// under two names is two entries rather than a collision.
const leaf = name => slug(name) || 'value';

export class Acquisitions {
  constructor(store, adapters) { this.store = store; this.adapters = adapters; }
  // Where an adapter's result is kept: the service, then whose account it is at that service.
  prefix(adapterId, label) {
    const adapter = this.adapters.get(adapterId);
    return secretPath(slug(adapter.service.name) + '/' + (slug(label) || 'account'));
  }
  // What the adapter produced, as entries. Every one of them says how it reaches a command, so delivery
  // never has to ask an adapter anything.
  entries(adapterId, secret, subject, prefix) {
    const adapter = this.adapters.get(adapterId);
    const { environment = {}, files = [], expo_session = null } = adapter.deliver(secret, { subject }) || {};
    const declared = new Set(adapter.variables || []);
    const rows = [];
    for (const [name, value] of Object.entries(environment)) {
      if (!declared.has(name)) throw new Error('Adapter ' + adapterId + ' delivered an undeclared variable: ' + name);
      rows.push({ path: prefix + '/' + leaf(name), content: Buffer.from(String(value), 'utf8'), session: null, readable: 0 });
    }
    for (const file of files) {
      if (!declared.has(file.env)) throw new Error('Adapter ' + adapterId + ' delivered an undeclared variable: ' + file.env);
      rows.push({ path: prefix + '/' + leaf(file.env), content: Buffer.from(file.content, 'utf8'), session: null, readable: 0 });
    }
    // A login session is handed to the command as the tool's own login state. The store does not read it.
    if (expo_session) rows.push({ path: prefix + '/session', content: Buffer.from(JSON.stringify(expo_session), 'utf8'), session: 'expo', readable: 0 });
    if (!rows.length) throw new Error('Adapter ' + adapterId + ' produced nothing to keep');
    for (const row of rows) if (row.content.length > VALUE_MAX * 4) fail(502, 'service_response', '受け取った内容が大きすぎます。');
    return rows;
  }
  // Records a new acquisition, or the same one obtained again.
  save(ownerId, adapterId, result, { keptBy = '', previous } = {}) {
    const adapter = this.adapters.get(adapterId);
    const facts = adapter.client.facts?.(result.secret) || {};
    const label = String(facts.label || result.subject).slice(0, 80);
    const prefix = previous ? previous.prefix : this.prefix(adapterId, label);
    return this.store.saveAcquisition(ownerId, { prefix, adapter: adapterId, subject: result.subject, label, keptBy,
      state: { renewal: result.secret, facts, expires_at: result.secret.expires_at ?? null } },
      this.entries(adapterId, result.secret, result.subject, prefix), previous);
  }
  // The view an adapter's client is given in place of the store. It sees only its own shape, and whatever it
  // saves is turned back into entries before the store accepts it.
  clientStore(acquisition) {
    const self = this;
    // Always read the row as it is now: a refresh that just ran must be what the next call sees.
    const current = () => self.store.acquisition(acquisition.owner_id, acquisition.prefix) ?? acquisition;
    return {
      secret: () => self.store.acquisitionState(current()).renewal,
      saveSecret(_row, secret) {
        const row = current(), adapter = self.adapters.get(row.adapter);
        const facts = adapter.client.facts?.(secret) || {};
        self.store.saveState(row, { renewal: secret, facts, expires_at: secret.expires_at ?? null },
          self.entries(row.adapter, secret, row.subject, row.prefix));
      },
      reconnectRequired: () => self.store.reconnectRequired(current()),
      transaction: fn => self.store.transaction(fn),
    };
  }
  // Brings an acquisition up to date before anything it keeps is handed over.
  async refresh(acquisition) {
    const adapter = this.adapters.get(acquisition.adapter);
    const row = { ...acquisition, status: acquisition.status, subject: acquisition.subject };
    await adapter.client.token(this.clientStore(acquisition), row, false);
  }
  state(acquisition) { return this.store.acquisitionState(acquisition); }
}
