import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';
import { definitionInput } from './service-definition.mjs';
import { schemesOf } from './catalog.mjs';
import { appFieldsOf, takesApps } from './apps.mjs';

// A service is where a connection works: what it is called, where its API and documentation are, where an app or a
// token for it is made, and the schemes by which Foundation comes to hold a connection for it. Foundation's catalog
// knows services by id; a holder may describe one the catalog does not know, as a resource of kind service, known by
// its resource id. Both are the same shape (service-definition.mjs) and are used the same way.
const COLUMNS = 'r.id,r.holder_id,r.kind,r.name,r.created_at,r.updated_at,s.definition';
const FROM = 'FROM resources r JOIN services s ON s.resource_id=r.id';
const UUID = /^[0-9a-f-]{36}$/;
export const SERVICES_MAX = 100;

export class Services {
  // entries: the catalog as it runs, each { definition, schemes } (catalog.mjs). fetcher: the network for services
  // holders describe, replaced in tests.
  constructor(store, resources, entries, { fetcher, authorization } = {}) {
    this.authorization = authorization;
    this.store = store; this.db = store.db; this.resources = resources; this.fetcher = fetcher;
    this.catalog = new Map(entries.map(entry => [entry.definition.id, entry]));
    this.built = new Map();
  }
  catalogIds() { return [...this.catalog.keys()]; }
  row(id) { return typeof id === 'string' && UUID.test(id) ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  find(holderId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? AND r.name=?`).get(holderId, resourceName(name)); }
  list(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? ORDER BY r.name, r.id`).all(holderId); }
  // Those others hold that a line reaches, where the rules let this principal read them.
  lent(principalId) {
    return this.db.prepare(`SELECT DISTINCT ${COLUMNS} ${FROM} JOIN relations l ON l.object_type='resource' AND l.object_id=r.id
      WHERE l.subject_id=? AND r.holder_id<>? ORDER BY r.name, r.id`).all(principalId, principalId)
      .filter(row => this.authorization.can(principalId, 'read', 'service', { id: row.id, holder: row.holder_id }));
  }
  // A service by reference: the catalog's id, or a described service's resource id. principalId, when given, must
  // be one the rules let read a described one.
  get(ref, principalId) {
    if (typeof ref !== 'string' || !ref) fail(400, 'invalid_service', 'サービスを指定してください。');
    const entry = this.catalog.get(ref);
    if (entry) return { ref, definition: entry.definition, catalog: true };
    const row = this.row(ref);
    if (!row || (principalId !== undefined && !this.authorization.can(principalId, 'read', 'service', { id: row.id, holder: row.holder_id }))) fail(404, 'not_found', 'サービスが見つかりません。');
    return { ref, definition: JSON.parse(row.definition), catalog: false, row };
  }
  // The schemes of a service as they run. A described service's are built from its definition and kept until it
  // changes.
  schemes(ref) {
    const entry = this.catalog.get(ref);
    if (entry) return entry.schemes;
    const row = this.row(ref);
    if (!row) fail(404, 'not_found', 'サービスが見つかりません。');
    const built = this.built.get(ref);
    if (built?.updated_at === row.updated_at) return built.schemes;
    const schemes = schemesOf(JSON.parse(row.definition), {}, this.fetcher ? { fetcher: this.fetcher } : {});
    this.built.set(ref, { updated_at: row.updated_at, schemes });
    return schemes;
  }
  scheme(ref, id) {
    const scheme = this.schemes(ref)[id];
    if (id === undefined) fail(409, 'auth_scheme_required', '接続方法を追加してください。');
    if (!scheme) fail(400, 'invalid_auth_scheme', 'このサービスでは、その方法で接続できません。');
    return scheme;
  }
  // What a connection or an app says of its service. A removed described service says only that it is gone.
  summary(ref) {
    if (!ref) return null;
    const entry = this.catalog.get(ref);
    if (entry) return { id: ref, name: entry.definition.name, ...(entry.definition.logo ? { logo: entry.definition.logo } : {}), catalog: true };
    const row = this.row(ref);
    return row ? { id: ref, name: JSON.parse(row.definition).name, catalog: false } : { id: ref, name: '削除されたサービス', catalog: false, removed: true };
  }
  // What anyone may know of a service: where it is, and how Foundation comes to hold a connection for it.
  describe(ref) {
    const { definition, catalog } = this.get(ref), schemes = this.schemes(ref), described = {};
    for (const [id, scheme] of Object.entries(schemes)) {
      const spec = definition.auth_schemes[id], common = { variables: scheme.variables, ...(spec.hint ? { hint: spec.hint } : {}) };
      if (id === 'oauth') described.oauth = { ...common, available: scheme.available, takes_apps: takesApps(scheme),
        foundation_app: takesApps(scheme) && Boolean(scheme.oauthClient.enabled),
        app_fields: takesApps(scheme) ? appFieldsOf(scheme).map(({ leading, ...field }) => field) : [],
        scopes: scheme.scopes ? { base: scheme.scopes.base, documentation_url: scheme.scopes.documentationUrl || '' } : null,
        can_revoke: typeof scheme.revoke === 'function', can_reconnect: scheme.canReconnect !== false };
      if (id === 'role') described.role = { ...common, available: scheme.available };
      if (id === 'token') described.token = { ...common, available: scheme.available, fields: scheme.fields, console: scheme.console };
    }
    return { id: ref, name: definition.name, ...(definition.logo ? { logo: definition.logo } : {}), catalog,
      ...Object.fromEntries(['api', 'docs', 'console'].filter(key => definition[key]).map(key => [key, definition[key]])), auth_schemes: described };
  }
  catalogView() { return this.catalogIds().map(ref => this.describe(ref)); }

  // Describing a service: the holder's definition, checked as the catalog's are. The same name again replaces it;
  // connections made for it go on under the new definition.
  put(holderId, name, input) {
    resourceName(name);
    const definition = definitionInput(input);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name);
      if (!existing && this.list(holderId).length >= SERVICES_MAX) fail(409, 'service_limit', `定義できるサービスは${SERVICES_MAX}件までです。`);
      const id = existing?.id ?? randomUUID();
      if (existing) {
        this.db.prepare('UPDATE services SET definition=? WHERE resource_id=?').run(JSON.stringify(definition), id);
        this.resources.touch(id);
      } else {
        this.resources.insert(id, holderId, 'service', name);
        this.db.prepare('INSERT INTO services (resource_id,definition) VALUES (?,?)').run(id, JSON.stringify(definition));
      }
      this.built.delete(id);
      return this.row(id);
    });
  }
  write(row, input) { return this.put(row.holder_id, row.name, input); }
  // Adding a method does not replace a definition read earlier, or alter an existing method.
  addSchemes(row, added) {
    return this.store.transaction(() => {
      const current = this.row(row.id);
      if (!current) fail(404, 'not_found', 'サービスが見つかりません。');
      const definition = JSON.parse(current.definition);
      const checked = definitionInput({ name: definition.name, auth_schemes: added });
      for (const [id, spec] of Object.entries(checked.auth_schemes)) {
        if (definition.auth_schemes[id] && !isDeepStrictEqual(definition.auth_schemes[id], spec)) {
          fail(409, 'auth_scheme_exists', 'この接続方法はすでに設定されています。開き直して確認してください。');
        }
      }
      return this.write(current, { ...definition, auth_schemes: { ...definition.auth_schemes, ...checked.auth_schemes } });
    });
  }
  rename(row, name) {
    resourceName(name);
    if (name !== row.name && this.find(row.holder_id, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.row(this.resources.rename(row, name).id);
  }
  // What refers to a described service: connections and apps, whoever holds them.
  dependents(row) {
    return this.db.prepare(`SELECT r.id, r.holder_id, r.kind, r.name FROM resources r LEFT JOIN connections c ON c.resource_id=r.id LEFT JOIN apps a ON a.resource_id=r.id
      WHERE c.service=? OR a.service=? ORDER BY r.created_at`).all(row.id, row.id);
  }
  // A service something still refers to stays: removing it would leave connections no scheme can use.
  remove(row) {
    const dependents = this.dependents(row);
    if (dependents.length) fail(409, 'service_in_use', `このサービスを使う接続やアプリが${dependents.length}件あります。先にそれらを削除してください。`, { dependents: dependents.length });
    this.built.delete(row.id);
    this.resources.remove(row);
  }
  view(row, { owner = false } = {}) {
    return { ...this.resources.view(row), definition: JSON.parse(row.definition), service: this.describe(row.id), ...(owner ? { dependents: this.dependents(row).length } : {}) };
  }
}
