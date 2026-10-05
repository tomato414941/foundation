import type { Database, Queryable } from './database.js';
import type { ActionName, ResourceKindName } from '../shared/contracts.js';
import { Action } from '../shared/contracts.js';
import { fail } from './errors.js';

export interface Actor { id: string; credentialId?: string; sessionId?: string; requestId?: string }
export interface ResourceIdentity { id: string; owner_id: string; kind: ResourceKindName }
const resourceActions: Record<ResourceKindName, ActionName[]> = {
  secret: ['read', 'update', 'delete', 'share', 'transfer', 'reveal', 'use'],
  connection: ['read', 'update', 'delete', 'share', 'transfer', 'use'],
  service: ['read', 'update', 'delete', 'share', 'transfer', 'use'],
  app: ['read', 'update', 'delete', 'share', 'transfer', 'use'],
  object: ['read', 'update', 'delete', 'share', 'transfer', 'use'],
  environment: ['read', 'update', 'delete', 'share', 'use', 'execute'],
  function: ['read', 'update', 'delete', 'share', 'transfer', 'execute'],
};
const agentActions: Record<ResourceKindName, ActionName[]> = {
  secret: ['read', 'create', 'update', 'delete', 'use'],
  connection: ['read', 'use'],
  service: ['read', 'create', 'update', 'delete'],
  app: ['read'],
  object: ['read', 'create', 'update', 'delete', 'use'],
  environment: ['read', 'create', 'use', 'execute', 'delete'],
  function: ['read', 'create', 'update', 'delete', 'execute'],
};
export class Authorization {
  constructor(readonly db: Database) {}
  async active(actor: Actor, connection: Queryable = this.db.pool) {
    const exists = await this.db.one<{ active: boolean }>(`SELECT EXISTS(SELECT 1 FROM principals WHERE id=$1)
      AND ($2::uuid IS NULL OR EXISTS(SELECT 1 FROM credentials c LEFT JOIN resources e ON e.id=c.environment_id WHERE c.id=$2 AND c.principal_id=$1 AND (c.expires_at IS NULL OR c.expires_at>now()) AND (c.environment_id IS NULL OR e.data->>'state'='running')))
      AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM sessions WHERE id=$3 AND principal_id=$1 AND expires_at>now())) AS active`, [actor.id, actor.credentialId ?? null, actor.sessionId ?? null], connection);
    if (!exists?.active) fail(401, 'unauthenticated', 'Sign in again to continue.');
  }
  async standsAs(actorId: string, connection: Queryable = this.db.pool): Promise<string[]> {
    const rows = await this.db.all<{ id: string }>(`WITH RECURSIVE standing(id) AS (
      SELECT id FROM principals WHERE id=$1
      UNION SELECT r.principal_id FROM relations r JOIN standing s ON s.id=r.subject_id WHERE r.relation IN ('owner','member')
    ) SELECT id FROM standing`, [actorId], connection);
    return rows.map(row => row.id);
  }
  async stands(actorId: string, principalId: string, connection: Queryable = this.db.pool) { return (await this.standsAs(actorId, connection)).includes(principalId); }
  async uses(actorId: string, principalId: string, connection: Queryable = this.db.pool): Promise<boolean> {
    const ids = await this.standsAs(actorId, connection);
    return ids.includes(principalId) || Boolean(await this.db.one('SELECT 1 FROM relations WHERE subject_id=ANY($1::uuid[]) AND principal_id=$2 AND relation=$3', [ids, principalId, 'agent'], connection));
  }
  async principal(actor: Actor, principalId: string, action: ActionName, connection: Queryable = this.db.pool): Promise<boolean> {
    await this.active(actor, connection);
    if (actor.requestId) return false;
    if (action === 'delete' || action === 'transfer') {
      const ids = await this.standsAs(actor.id, connection);
      return Boolean(await this.db.one('SELECT 1 FROM relations WHERE principal_id=$1 AND relation=$2 AND subject_id=ANY($3::uuid[])', [principalId, 'owner', ids], connection));
    }
    if (await this.stands(actor.id, principalId, connection)) return true;
    if (['read', 'use', 'execute'].includes(action) && await this.uses(actor.id, principalId, connection)) return true;
    return Boolean(await this.db.one('SELECT 1 FROM principal_grants WHERE target_id=$1 AND principal_id=ANY($2::uuid[]) AND $3=ANY(actions)', [principalId, await this.standsAs(actor.id, connection), action], connection));
  }
  async resource(actor: Actor, resource: ResourceIdentity, action: ActionName, connection: Queryable = this.db.pool): Promise<boolean> {
    await this.active(actor, connection);
    if (actor.requestId || !resourceActions[resource.kind].includes(action)) return false;
    const ids = await this.standsAs(actor.id, connection);
    if (ids.includes(resource.owner_id)) return action !== 'transfer' || resource.kind !== 'environment';
    if (agentActions[resource.kind].includes(action) && await this.uses(actor.id, resource.owner_id, connection)) return true;
    return Boolean(await this.db.one('SELECT 1 FROM grants WHERE resource_id=$1 AND principal_id=ANY($2::uuid[]) AND $3=ANY(actions)', [resource.id, ids, action], connection));
  }
  async canCreate(actor: Actor, ownerId: string, kind: ResourceKindName, connection: Queryable = this.db.pool): Promise<boolean> {
    await this.active(actor, connection);
    if (actor.requestId) return false;
    return await this.principal(actor, ownerId, 'create', connection) || agentActions[kind].includes('create') && await this.uses(actor.id, ownerId, connection);
  }
  async requirePrincipal(actor: Actor, principalId: string, action: ActionName, connection: Queryable = this.db.pool) {
    if (!await this.principal(actor, principalId, action, connection)) fail(403, 'forbidden', 'You do not have permission to perform this action.');
  }
  async requireResource(actor: Actor, resource: ResourceIdentity, action: ActionName, connection: Queryable = this.db.pool) {
    if (!await this.resource(actor, resource, action, connection)) fail(403, 'forbidden', 'You do not have permission to perform this action.');
  }
  async actionsForResources(actor: Actor, resources: ResourceIdentity[]): Promise<Map<string, ActionName[]>> {
    await this.active(actor);
    const result = new Map<string, ActionName[]>();
    if (actor.requestId) return result;
    const standing = await this.standsAs(actor.id);
    const agents = await this.db.all<{ principal_id: string }>("SELECT principal_id FROM relations WHERE subject_id=ANY($1::uuid[]) AND relation='agent'", [standing]);
    const usable = new Set(agents.map(row => row.principal_id));
    const grants = await this.db.all<{ resource_id: string; actions: ActionName[] }>('SELECT resource_id,actions FROM grants WHERE principal_id=ANY($1::uuid[]) AND resource_id=ANY($2::uuid[])', [standing, resources.map(resource => resource.id)]);
    for (const resource of resources) {
      const actions = new Set<ActionName>(standing.includes(resource.owner_id) ? resourceActions[resource.kind] : usable.has(resource.owner_id) ? agentActions[resource.kind].filter(action => resourceActions[resource.kind].includes(action)) : []);
      for (const grant of grants) if (grant.resource_id === resource.id) for (const action of grant.actions) if (resourceActions[resource.kind].includes(action)) actions.add(action);
      result.set(resource.id, [...actions]);
    }
    return result;
  }
  async resourceActions(actor: Actor, resource: ResourceIdentity) { return (await this.actionsForResources(actor, [resource])).get(resource.id) ?? []; }
  async principalActions(actor: Actor, id: string): Promise<ActionName[]> {
    await this.active(actor);
    if (actor.requestId) return [];
    const standing = await this.standsAs(actor.id);
    const owns = Boolean(await this.db.one("SELECT 1 FROM relations WHERE subject_id=ANY($1::uuid[]) AND principal_id=$2 AND relation='owner'", [standing, id]));
    if (standing.includes(id)) return Action.options.filter(action => owns || !['delete', 'transfer'].includes(action));
    const actions: ActionName[] = await this.uses(actor.id, id) ? ['read', 'use', 'execute'] : [];
    const grants = await this.db.all<{actions: ActionName[]}>('SELECT actions FROM principal_grants WHERE target_id=$1 AND principal_id=ANY($2::uuid[])', [id, standing]);
    return [...new Set([...actions, ...grants.flatMap(grant => grant.actions).filter(action => !['delete', 'transfer'].includes(action))])];
  }
}
