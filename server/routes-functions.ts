import { z } from 'zod';
import type { ApiApp } from './app.js';
import { actor } from './app.js';
import type { Context } from './context.js';
import { fail } from './errors.js';
import { Id, IdParams, Json, JsonObject, PageQuery, FunctionResource, FunctionExecutionSettings, listOf } from '../shared/contracts.js';
import { KeyBinding } from '../shared/authority.js';
import { CreateFunction, UpdateFunction, FunctionSettingsWrite, Invocation, InvocationCompletion, ClaimedInvocation } from '../shared/function-api.js';
import type { Actor } from './authorization.js';
import { FunctionSave, FunctionConfigure } from '../shared/executions.js';
import { ProtectedRead } from '../shared/protocol.js';

export async function routesFunctions(app: ApiApp, context: Context) {
  const { functions, invocations, resources, authorization, custody, delegation, executions } = context;
  const publish = async (who: Actor, input: z.infer<typeof FunctionSave>, proof: unknown) => {
    const execution = await executions.start(who, [{ name: 'function.save', input: JsonObject.parse(input) }]);
    return (await executions.complete(who, execution.id, 0, Json.parse(proof))).results[0];
  };
  const selected = async (id: string) => {
    const row = await resources.get(id);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a function.');
    return row;
  };
  app.get('/api/functions', { schema: { querystring: PageQuery.extend({ query: z.string().max(200).optional() }),
    response: { 200: listOf(FunctionResource) } } }, async request => {
    const who = actor(request), ids = [...new Set([...await authorization.find(who.id, 'function', 'read'),
      ...await authorization.find(who.id, 'function', 'execute')])];
    const limit = request.query.limit;
    const rows = await resources.db.all<import('./resources.js').ResourceRow>(
      `SELECT * FROM resources WHERE kind='function' AND id=ANY($1::uuid[]) AND ($2::uuid IS NULL OR id>$2)
       AND ($3::text IS NULL OR strpos(lower(name),lower($3))>0) ORDER BY id LIMIT $4`,
      [ids, request.query.after ?? null, request.query.query ?? null, limit + 1]);
    return { items: await Promise.all(rows.slice(0, limit).map(async row => FunctionResource.parse(await resources.view(who, row)))),
      next: rows.length > limit ? rows[limit - 1]!.id : null };
  });
  app.post('/api/principals/:id/functions', { bodyLimit: 40 * 1024 * 1024, schema: { params: IdParams,
    body: CreateFunction, response: { 201: FunctionResource } } }, async (request, reply) => {
    const { authorization: proof, ...input } = request.body;
    return reply.code(201).send(FunctionResource.parse(await publish(actor(request), { ...input, ownerId: request.params.id }, proof)));
  });
  app.get('/api/functions/:id', { schema: { params: IdParams, response: { 200: FunctionResource } } }, async request => {
    const row = await selected(request.params.id), who = actor(request), permissions = await authorization.actions(who, row);
    if (!permissions.includes('read') && !permissions.includes('execute')) fail(403, 'forbidden', 'You cannot access this function.');
    return FunctionResource.parse(await resources.view(who, row, permissions));
  });
  app.put('/api/functions/:id', { bodyLimit: 40 * 1024 * 1024, schema: { params: IdParams,
    body: UpdateFunction, response: { 200: FunctionResource } } }, async request => {
    const row = await selected(request.params.id), { authorization: proof, ...input } = request.body;
    return FunctionResource.parse(await publish(actor(request), { ...input, ownerId: row.owner_id, resourceId: row.id }, proof));
  });
  app.get('/api/functions/:id/authorizations', { schema: { params: IdParams, response: { 200: listOf(ProtectedRead) } } },
    request => functions.authorizations(actor(request), request.params.id, custody));
  app.get('/api/functions/:id/execution-settings', { schema: { params: IdParams, response: { 200: FunctionExecutionSettings } } },
    request => functions.settings(actor(request), request.params.id));
  app.put('/api/functions/:id/execution-settings', { bodyLimit: 40 * 1024 * 1024, schema: { params: IdParams,
    body: FunctionConfigure.omit({ functionId: true }).extend({ authorization: FunctionSettingsWrite }).strict(),
    response: { 200: FunctionExecutionSettings } } }, async request => {
    const who = actor(request), { authorization: proof, ...input } = request.body;
    const execution = await executions.start(who, [{ name: 'function.configure',
      input: JsonObject.parse({ functionId: request.params.id, ...input }) }]);
    await executions.complete(who, execution.id, 0, Json.parse(proof));
    return functions.settings(who, request.params.id);
  });
  app.get('/api/functions/:id/output-recipient', { schema: { params: IdParams,
    response: { 200: z.object({ executor: KeyBinding }) } } }, async request => {
    const current = await functions.execution(actor(request), request.params.id, custody, delegation);
    return { executor: current.settings.executor! };
  });
  app.get('/api/runtime/principals/:id/functions', { schema: { params: IdParams, querystring: PageQuery,
    response: { 200: listOf(Invocation) } } }, request => invocations.list(actor(request), request.params.id, request.query.limit, request.query.after));
  app.get('/api/runtime/functions/:id', { schema: { params: IdParams, response: { 200: Invocation } } },
    request => invocations.get(actor(request), request.params.id));
  app.post('/api/environments/:id/invocations/claim', { schema: { params: IdParams, body: z.object({}).strict(),
    response: { 200: ClaimedInvocation } } }, request => invocations.claim(actor(request), request.params.id));
  const lease = z.object({ lease: Id }).strict();
  app.post('/api/runtime/functions/:id/dispatch', { schema: { params: IdParams, body: lease,
    response: { 200: z.object({ ok: z.literal(true) }) } } }, request => invocations.dispatch(actor(request), request.params.id, request.body.lease));
  app.post('/api/runtime/functions/:id/renew', { schema: { params: IdParams, body: lease,
    response: { 200: z.object({ active: z.boolean(), reason: z.enum(['cancelled', 'authorization_changed', 'lease_lost']).optional() }) } } },
    request => invocations.renew(actor(request), request.params.id, request.body.lease));
  app.post('/api/runtime/functions/:id/finish', { bodyLimit: 8 * 1024 * 1024, schema: { params: IdParams,
    body: lease.extend({ completion: InvocationCompletion }), response: { 200: Invocation } } },
    request => invocations.finish(actor(request), request.params.id, request.body.lease, request.body.completion));
}
