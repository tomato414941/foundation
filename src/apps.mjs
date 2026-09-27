import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { holdingName } from './holdings.mjs';
import { withOwnClient } from './connectors.mjs';

// An app is the name a service knows Foundation by when someone authorizes it: an OAuth client, registered at the
// service by whoever holds it. Foundation offers one per service, from its own configuration; anyone may hold more of
// their own. The two are the same kind of thing, and differ only in who holds them.
//
// Three layers, each with its own grain: a service (what a connector knows), apps through which it is authorized,
// and connections - one account's authorization, with the scopes it gave - each made through exactly one app. A
// connection renews and revokes through its app. Changing an app's secret keeps its connections; removing an app
// stops them, as removing it at the service would, and they wait to be connected again through another.
//
// An app is used by Foundation alone. Nobody reads its secret back: not its holder, and not anyone given a line to
// it. A viewer line lets someone connect their own accounts through the app; an editor line also lets them change
// its secret.
export const FOUNDATION_APP = 'foundation';
const FIELDS = { client_id: 'clientId', client_secret: 'clientSecret', ru_name: 'ruName' };
const COLUMNS = 'h.id,h.holder_id,h.kind,h.name,h.created_at,h.updated_at,a.connector,a.client_id';
const FROM = 'FROM holdings h JOIN apps a ON a.holding_id=h.id';

export class Apps {
  constructor(store, holdings, connectors) {
    Object.assign(this, { store, holdings, connectors, db: store.db, vault: store.vault });
  }
  binding(row) { return `app:${row.holder_id}:${row.id}`; }
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', 'アプリが見つかりません。');
    return row;
  }
  find(holderId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.holder_id=? AND h.name=?`).get(holderId, holdingName(name)); }
  // A holder's own apps, and those others drew them a line to.
  list(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.holder_id=? ORDER BY a.connector, h.name, h.id`).all(holderId); }
  lent(principalId) {
    return this.db.prepare(`SELECT DISTINCT ${COLUMNS} ${FROM} JOIN relations r ON r.object_type='holding' AND r.object_id=h.id
      WHERE r.subject_id=? AND r.relation IN ('viewer','editor') AND h.holder_id<>? ORDER BY a.connector, h.name, h.id`).all(principalId, principalId);
  }

  // Whether a principal may connect through an app: its own, or one it was drawn a line to.
  usableBy(principalId, id) {
    const row = this.get(id);
    return Boolean(row && (row.holder_id === principalId || this.lent(principalId).some(item => item.id === id)));
  }
  // What an app of this connector must hold: its client ID and secret, and whatever else the service needs (eBay: RuName).
  fields(connector) {
    if (typeof connector.withClient !== 'function' || !connector.oauthClient) fail(400, 'app_unsupported', 'この接続先では自分のアプリを使えません。');
    return connector.clientFields ?? ['client_id', 'client_secret'];
  }
  values(connector, input) {
    const wanted = this.fields(connector), values = {};
    for (const key of wanted) {
      const value = typeof input?.[key] === 'string' ? input[key].trim() : '';
      if (!value || value.length > 2048 || /[\x00-\x20\x7f]/.test(value)) fail(400, 'invalid_app', 'アプリのIDと秘密（eBayはRuNameも）を入力してください。');
      values[key] = value;
    }
    return values;
  }
  // Registering an app, or giving one of the same name new values (a rotated secret). Its connections go on.
  put(holderId, { name, connector: connectorId, ...input }) {
    holdingName(name);
    const connector = this.connectors.get(connectorId), values = this.values(connector, input);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name);
      if (existing && existing.connector !== connector.id) fail(409, 'name_taken', 'その名前は別の接続先のアプリに使われています。');
      const id = existing?.id ?? randomUUID(), row = { id, holder_id: holderId };
      const { client_id, ...secret } = values, sealed = this.vault.seal(secret, this.binding(row));
      if (existing) {
        this.db.prepare('UPDATE apps SET client_id=?, secret=? WHERE holding_id=?').run(client_id, sealed, id);
        this.holdings.touch(id);
      } else {
        this.holdings.insert(id, holderId, 'app', name);
        this.db.prepare('INSERT INTO apps (holding_id,connector,client_id,secret) VALUES (?,?,?,?)').run(id, connector.id, client_id, sealed);
      }
      return this.get(id);
    });
  }
  // New values for the same app, by id: what an editor may do.
  write(row, input) { return this.put(row.holder_id, { name: row.name, connector: row.connector, ...input }); }
  rename(row, name) {
    holdingName(name);
    if (name !== row.name && this.find(row.holder_id, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.get(this.holdings.rename(row, name).id);
  }
  credentials(row) {
    const secret = this.vault.open(this.db.prepare('SELECT secret FROM apps WHERE holding_id=?').get(row.id).secret, this.binding(row));
    return { clientId: row.client_id, ...Object.fromEntries(Object.entries(secret).map(([key, value]) => [FIELDS[key], value])) };
  }
  // The connector as it speaks through this app.
  connector(row) { return withOwnClient(this.connectors.get(row.connector), this.credentials(row)); }
  // The connections made through an app, whoever holds them.
  dependents(row) {
    return this.db.prepare(`SELECT h.id, h.holder_id, h.name FROM grants g JOIN holdings h ON h.id=g.holding_id WHERE g.app_id=? AND g.status<>'disconnecting' ORDER BY h.created_at`).all(row.id);
  }
  // Removing an app is what removing it at the service does: its connections can no longer renew. They stay, with
  // their scopes, waiting to be connected again through another app.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare("UPDATE grants SET app_id=NULL, status='reconnect_required', generation=generation+1 WHERE app_id=? AND status<>'disconnecting'").run(row.id);
      this.holdings.remove(row);
    });
  }

  // Foundation's own app for a connector: from its configuration, listed like any app, never stored.
  offered(connector) {
    return connector.available && typeof connector.withClient === 'function' && connector.oauthClient
      ? { id: FOUNDATION_APP, kind: 'app', name: 'Foundationのアプリ', connector: connector.id, service: connector.service, foundation: true } : null;
  }
  offeredAll() { return this.connectors.ids().map(id => this.offered(this.connectors.get(id))).filter(Boolean); }
  view(row, { owner = false, connections } = {}) {
    const connector = this.connectors.get(row.connector);
    return { ...this.holdings.view(row), connector: row.connector, service: connector.service, client_id: row.client_id, foundation: false,
      ...(owner ? { connections: connections ?? this.dependents(row).length } : {}) };
  }
}
