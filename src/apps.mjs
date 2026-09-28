import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { holdingName } from './holdings.mjs';

// An app is the name a service knows Foundation by when someone authorizes it: an OAuth client, registered at the
// service by whoever holds it. Foundation offers one per service, from its own configuration; anyone may hold more of
// their own. The two are the same kind of thing, and differ only in who holds them.
//
// Three layers, each with its own grain: a service (what a connector knows), apps through which it is authorized,
// and connections - one account's authorization, with the scopes it gave - each made through exactly one app. A
// connection renews and revokes through its app. Changing an app's secret keeps its connections; removing an app
// stops them, as removing it at the service would, and they wait to be connected again through another.
//
// An app is used by Foundation alone. What it holds is either said (its client ID, and whatever else is not secret)
// or sealed (its client secret): nobody reads a sealed value back, not its holder and not anyone given a line to it.
// A viewer line lets someone connect their own accounts through the app; an editor line also lets them change it.
export const FOUNDATION_APP = 'foundation';
// What any app holds. A connector adds what its service needs as well (eBay: its RuName; a generic OAuth 2.0 app:
// where the service authorizes and hands out tokens).
export const APP_FIELDS = [
  { name: 'client_id', label: 'クライアントID', required: true },
  { name: 'client_secret', label: 'クライアントシークレット', required: true, sealed: true },
];
const COLUMNS = 'h.id,h.holder_id,h.kind,h.name,h.created_at,h.updated_at,a.connector,a.client_id,a.settings';
const FROM = 'FROM holdings h JOIN apps a ON a.holding_id=h.id';
const camel = name => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

// What an app of a connector holds, in the order it is asked for: what the service is (when the app says so), the
// client, then the rest.
export function appFieldsOf(connector) {
  const own = connector.appFields ?? [];
  return [...own.filter(field => field.leading), ...APP_FIELDS, ...own.filter(field => !field.leading)];
}
// Whether a connector's service is authorized through apps, and so whether someone may bring their own.
export const takesApps = connector => typeof connector.withClient === 'function' && Boolean(connector.oauthClient);
// The connector as it speaks through an app: the same connector, built around a client with that app's values.
function through(connector, values) {
  const base = connector.oauthClient;
  return connector.withClient(Object.assign(Object.create(Object.getPrototypeOf(base)), base, values, { enabled: true }));
}

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

  // What an app of this connector holds.
  fields(connector) {
    if (!takesApps(connector)) fail(400, 'app_unsupported', 'この接続先では自分のアプリを使えません。');
    return appFieldsOf(connector);
  }
  // The values given for an app, each checked: said values in the clear, sealed ones kept apart.
  values(connector, input) {
    const said = {}, sealed = {};
    for (const field of this.fields(connector)) {
      const given = typeof input?.[field.name] === 'string' ? input[field.name].trim() : '';
      if (!given) { if (field.required) fail(400, 'invalid_app', `${field.label}を入力してください。`); continue; }
      if (given.length > 2048 || /[\x00-\x1f\x7f]/.test(given) || (!field.text && /\s/.test(given))) fail(400, 'invalid_app', `${field.label}を確認してください。`);
      field.check?.(given);
      (field.sealed ? sealed : said)[field.name] = given;
    }
    return { said, sealed };
  }
  // Registering an app, or giving one of the same name new values (a rotated secret). Its connections go on.
  put(holderId, { name, connector: connectorId, ...input }) {
    holdingName(name);
    const connector = this.connectors.get(connectorId), { said: { client_id, ...settings }, sealed } = this.values(connector, input);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name);
      if (existing && existing.connector !== connector.id) fail(409, 'name_taken', 'その名前は別の接続先のアプリに使われています。');
      const id = existing?.id ?? randomUUID(), secret = this.vault.seal(sealed, this.binding({ id, holder_id: holderId }));
      if (existing) {
        this.db.prepare('UPDATE apps SET client_id=?, settings=?, secret=? WHERE holding_id=?').run(client_id, JSON.stringify(settings), secret, id);
        this.holdings.touch(id);
      } else {
        this.holdings.insert(id, holderId, 'app', name);
        this.db.prepare('INSERT INTO apps (holding_id,connector,client_id,settings,secret) VALUES (?,?,?,?,?)').run(id, connector.id, client_id, JSON.stringify(settings), secret);
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
  // Everything the app holds, as the connector's client takes it.
  clientValues(row) {
    const sealed = this.vault.open(this.db.prepare('SELECT secret FROM apps WHERE holding_id=?').get(row.id).secret, this.binding(row));
    return Object.fromEntries(Object.entries({ client_id: row.client_id, ...JSON.parse(row.settings), ...sealed }).map(([key, value]) => [camel(key), value]));
  }
  // The connector to speak to a service with, through the app a connection names: one held, or Foundation's own.
  connector(connectorId, appId) {
    const connector = this.connectors.get(connectorId);
    if (!appId || appId === FOUNDATION_APP) return connector;
    const row = this.at(appId);
    if (row.connector !== connector.id) fail(400, 'app_mismatch', 'このアプリは別の接続先のものです。');
    return through(connector, this.clientValues(row));
  }
  // The connections made through an app, whoever holds them.
  dependents(row) {
    return this.db.prepare(`SELECT h.id, h.holder_id, h.name FROM grants g JOIN holdings h ON h.id=g.holding_id WHERE g.app_id=? AND g.status<>'disconnecting' ORDER BY h.created_at`).all(row.id);
  }
  // Removing an app is what removing it at the service does: its connections can no longer renew. They stay, with
  // their scopes and without an app, waiting to be connected again through another.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare("UPDATE grants SET app_id=NULL, status='reconnect_required', generation=generation+1 WHERE app_id=? AND status<>'disconnecting'").run(row.id);
      this.holdings.remove(row);
    });
  }

  // Foundation's own app for a connector, when its configuration has one: listed like any app, never stored.
  offered(connector) {
    return takesApps(connector) && connector.oauthClient.enabled
      ? { id: FOUNDATION_APP, kind: 'app', name: 'Foundationのアプリ', connector: connector.id, service: connector.service, foundation: true } : null;
  }
  offeredAll() { return this.connectors.ids().map(id => this.offered(this.connectors.get(id))).filter(Boolean); }
  // An app as a connection or a request names it: which one, by what name, and whether it is Foundation's. A
  // connection whose app was removed names none.
  reference(appId) {
    if (appId === FOUNDATION_APP) return { id: FOUNDATION_APP, name: 'Foundationのアプリ', foundation: true };
    const row = appId ? this.get(appId) : undefined;
    return row ? { id: row.id, name: row.name, foundation: false } : null;
  }
  // The service an app is for: the connector's, or - for a connector that knows services only through their apps -
  // the one the app names.
  service(connectorId, appId) {
    const connector = this.connectors.get(connectorId), row = appId && appId !== FOUNDATION_APP ? this.get(appId) : undefined;
    return row && typeof connector.serviceFor === 'function' ? connector.serviceFor(JSON.parse(row.settings)) : connector.service;
  }
  view(row, { owner = false } = {}) {
    return { ...this.holdings.view(row), connector: row.connector, service: this.service(row.connector, row.id), client_id: row.client_id, settings: JSON.parse(row.settings),
      foundation: false, ...(owner ? { connections: this.dependents(row).length } : {}) };
  }
}
