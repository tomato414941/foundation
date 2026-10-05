import { readdir, readFile } from 'node:fs/promises';
import { ServiceDefinition, CatalogEntry } from '../shared/contracts.js';
import type { ServiceDescription, CatalogService } from '../shared/contracts.js';
import type { Resources } from './resources.js';
import type { Actor } from './authorization.js';
import type { Configuration } from './config.js';
import { fail } from './errors.js';

export class Catalog {
  private constructor(readonly definitions: Map<string,ServiceDescription>, readonly resources: Resources, readonly config: Configuration) {}
  static async load(resources: Resources, config: Configuration) {
    const directory = new URL('./catalog/',import.meta.url), definitions = new Map<string,ServiceDescription>();
    for(const filename of (await readdir(directory)).filter(name => name.endsWith('.json')).sort()) {
      const {id,...data} = JSON.parse(await readFile(new URL(filename,directory),'utf8'));
      definitions.set(String(id),ServiceDefinition.parse(data));
    }
    return new Catalog(definitions, resources, config);
  }
  async get(actor: Actor, id: string): Promise<ServiceDescription> {
    const builtin = this.definitions.get(id); if(builtin) return builtin;
    if(!/^[0-9a-f-]{36}$/.test(id)) fail(404,'not_found','The service was not found.');
    const row = await this.resources.get(id);
    if(row.kind !== 'service') fail(404,'not_found','The service was not found.');
    await this.resources.authorization.requireResource(actor,row,'use');
    return ServiceDefinition.parse(row.data);
  }
  async list(actor: Actor): Promise<CatalogService[]> {
    const ids = await this.resources.authorization.standsAs(actor.id);
    const custom = await this.resources.db.all<{id:string;data:ServiceDescription}>(`SELECT r.id,r.data FROM resources r WHERE r.kind='service' AND (r.owner_id=ANY($1::uuid[]) OR EXISTS(SELECT 1 FROM grants g WHERE g.resource_id=r.id AND g.principal_id=ANY($1::uuid[]) AND 'use'=ANY(g.actions)))`,[ids]);
    return [...this.definitions.entries(),...custom.map(row => [row.id,ServiceDefinition.parse(row.data)] as const)].map(([id,data]) => CatalogEntry.parse({id,...data,builtin:this.definitions.has(id),available:Object.keys(data.auth).filter(kind => kind === 'token' || kind === 'role' && this.config.FOUNDATION_AWS_PRINCIPAL_ARN || kind === 'oauth' && (data.auth.oauth?.adapter === 'openrouter' || this.config.oauthApps[id]))})).sort((a,b) => a.name.localeCompare(b.name));
  }
}
