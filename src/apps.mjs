import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';

// An app is the name a service knows Foundation by when someone authorizes it: an OAuth client, registered at the
// service by whoever holds it. Foundation offers one per service, from its own configuration; anyone may hold more of
// their own. The two are the same kind of thing, and differ only in who holds them.
//
// Three layers, each with its own grain: a service (services.mjs), apps through which it is authorized, and the
// connections made through them - one account's authorization, with the scopes it gave - each through exactly one
// app. A connection renews and revokes through its app. Changing an app's secret keeps its connections; removing an
// app stops them, as removing it at the service would, and they wait to be connected again through another.
//
// An app is used by Foundation alone. What it holds is either said (its client ID, and whatever else is not secret)
// or sealed (its client secret): nobody reads a sealed value back, not its holder and not anyone given a line to it.
// A viewer line lets someone connect their own accounts through the app; an editor line also lets them change it.
export const FOUNDATION_APP = 'foundation';
// What any app holds. A service adds what it needs as well (eBay: its RuName; kintone: its domain).
export const APP_FIELDS = [
  { name: 'client_id', label: 'クライアントID', required: true },
  { name: 'client_secret', label: 'クライアントシークレット', required: true, sealed: true },
];
const COLUMNS = 'r.id,r.holder_id,r.kind,r.name,r.created_at,r.updated_at,a.service,a.client_id,a.settings';
const FROM = 'FROM resources r JOIN apps a ON a.resource_id=r.id';
const camel = name => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

// What an app of a scheme holds, in the order it is asked for: where the service is (when the app says so), the
// client, then the rest.
export function appFieldsOf(scheme) {
  const own = scheme.appFields ?? [];
  return [...own.filter(field => field.leading), ...APP_FIELDS, ...own.filter(field => !field.leading)];
}
// Whether a scheme is authorized through apps, and so whether someone may bring their own.
export const takesApps = scheme => scheme?.kind === 'oauth' && typeof scheme.withClient === 'function' && Boolean(scheme.oauthClient);
// The scheme as it speaks through an app: the same scheme, built around a client with that app's values.
function through(scheme, values) {
  const base = scheme.oauthClient;
  return scheme.withClient(Object.assign(Object.create(Object.getPrototypeOf(base)), base, values, { enabled: true }));
}

export class Apps {
  constructor(store, resources, services) {
    Object.assign(this, { store, resources, services, db: store.db, vault: store.vault });
  }
  binding(row) { return `app:${row.holder_id}:${row.id}`; }
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  at(id) {
    const row = this.get(id);
    if (!row) fail(404, 'not_found', 'アプリが見つかりません。');
    return row;
  }
  find(holderId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? AND r.name=?`).get(holderId, resourceName(name)); }
  // A holder's own apps, and those others drew them a line to.
  list(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? ORDER BY a.service, r.name, r.id`).all(holderId); }
  lent(principalId) {
    return this.db.prepare(`SELECT DISTINCT ${COLUMNS} ${FROM} JOIN relations l ON l.object_type='resource' AND l.object_id=r.id
      WHERE l.subject_id=? AND r.holder_id<>? ORDER BY a.service, r.name, r.id`).all(principalId, principalId)
      .filter(row => this.services.authorization.can(principalId, 'read', 'app', { id: row.id, holder: row.holder_id }));
  }

  // What an app of this service holds.
  fields(serviceRef) {
    const scheme = this.services.scheme(serviceRef, 'oauth');
    if (!takesApps(scheme)) fail(400, 'app_unsupported', 'このサービスでは自分のアプリを使えません。');
    return appFieldsOf(scheme);
  }
  // The values given for an app, each checked: said values in the clear, sealed ones kept apart.
  values(serviceRef, input) {
    const said = {}, sealed = {};
    for (const field of this.fields(serviceRef)) {
      const given = typeof input?.[field.name] === 'string' ? input[field.name].trim() : '';
      if (!given) { if (field.required) fail(400, 'invalid_app', `${field.label}を入力してください。`); continue; }
      if (given.length > 2048 || /[\x00-\x1f\x7f\s]/.test(given) || (field.pattern && !new RegExp(field.pattern).test(given))) fail(400, 'invalid_app', `${field.label}を確認してください。`);
      (field.sealed ? sealed : said)[field.name] = given;
    }
    return { said, sealed };
  }
  // Registering an app, or giving one of the same name new values (a rotated secret). Its connections go on.
  put(holderId, { name, service, ...input }) {
    resourceName(name);
    const { ref } = this.services.get(service, holderId), { said: { client_id, ...settings }, sealed } = this.values(ref, input);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name);
      if (existing && existing.service !== ref) fail(409, 'name_taken', 'その名前は別のサービスのアプリに使われています。');
      const id = existing?.id ?? randomUUID(), secret = this.vault.seal(sealed, this.binding({ id, holder_id: holderId }));
      if (existing) {
        this.db.prepare('UPDATE apps SET client_id=?, settings=?, secret=? WHERE resource_id=?').run(client_id, JSON.stringify(settings), secret, id);
        this.resources.touch(id);
      } else {
        this.resources.insert(id, holderId, 'app', name);
        this.db.prepare('INSERT INTO apps (resource_id,service,client_id,settings,secret) VALUES (?,?,?,?,?)').run(id, ref, client_id, JSON.stringify(settings), secret);
      }
      return this.get(id);
    });
  }
  // New values for the same app, by id: what an editor may do.
  write(row, input) { return this.put(row.holder_id, { name: row.name, service: row.service, ...input }); }
  rename(row, name) {
    resourceName(name);
    if (name !== row.name && this.find(row.holder_id, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.get(this.resources.rename(row, name).id);
  }
  // Everything the app holds, as the scheme's client takes it.
  clientValues(row) {
    const sealed = this.vault.open(this.db.prepare('SELECT secret FROM apps WHERE resource_id=?').get(row.id).secret, this.binding(row));
    return Object.fromEntries(Object.entries({ client_id: row.client_id, ...JSON.parse(row.settings), ...sealed }).map(([key, value]) => [camel(key), value]));
  }
  // The OAuth scheme to speak to a service with, through the app a connection names: one held, or Foundation's own.
  scheme(serviceRef, appId) {
    const scheme = this.services.scheme(serviceRef, 'oauth');
    if (!appId || appId === FOUNDATION_APP) return scheme;
    const row = this.at(appId);
    if (row.service !== serviceRef) fail(400, 'app_mismatch', 'このアプリは別のサービスのものです。');
    return through(scheme, this.clientValues(row));
  }
  // The connections made through an app, whoever holds them.
  dependents(row) {
    return this.db.prepare(`SELECT r.id, r.holder_id, r.name FROM connections c JOIN resources r ON r.id=c.resource_id WHERE c.app_id=? AND c.status<>'disconnecting' ORDER BY r.created_at`).all(row.id);
  }
  // Removing an app is what removing it at the service does: its connections can no longer renew. They stay, with
  // their scopes and without an app, waiting to be connected again through another.
  remove(row) {
    this.store.transaction(() => {
      this.db.prepare("UPDATE connections SET app_id=NULL, status='reconnect_required', generation=generation+1 WHERE app_id=? AND status<>'disconnecting'").run(row.id);
      this.resources.remove(row);
    });
  }

  // Foundation's own app for a service, when its configuration has one: listed like any app, never stored.
  offered(serviceRef) {
    let scheme;
    try { scheme = this.services.scheme(serviceRef, 'oauth'); } catch { return null; }
    return takesApps(scheme) && scheme.oauthClient.enabled
      ? { id: FOUNDATION_APP, kind: 'app', name: 'Foundationのアプリ', service: this.services.summary(serviceRef), foundation: true } : null;
  }
  offeredAll() { return this.services.catalogIds().map(ref => this.offered(ref)).filter(Boolean); }
  // An app as a connection or a request names it: which one, by what name, and whether it is Foundation's. A
  // connection whose app was removed names none.
  reference(appId) {
    if (appId === FOUNDATION_APP) return { id: FOUNDATION_APP, name: 'Foundationのアプリ', foundation: true };
    const row = appId ? this.get(appId) : undefined;
    return row ? { id: row.id, name: row.name, foundation: false } : null;
  }
  view(row, { owner = false } = {}) {
    return { ...this.resources.view(row), service: this.services.summary(row.service), client_id: row.client_id, settings: JSON.parse(row.settings),
      foundation: false, ...(owner ? { connections: this.dependents(row).length } : {}) };
  }
}
