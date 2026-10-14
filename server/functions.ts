import { FUNCTION_RUNTIME_VERSION, HTTP_RUNTIME_VERSION } from '../shared/runtime-protocol.js';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Custody } from './custody.js';
import type { Delegation } from './delegation.js';
import { publicUrl } from './transport.js';
import { FunctionDefinition, FunctionExecutionSettings, validInputName } from '../shared/contracts.js';
import type { FunctionSpec, HttpRequestInput, JsonValue, SourceReference } from '../shared/contracts.js';
import { FunctionSave, FunctionConfigure } from '../shared/executions.js';
import { FunctionWrite, FunctionSettingsWrite, verifyFunction, verifyFunctionSettings } from '../shared/function-api.js';
import type { SettingsApproval } from '../shared/function-api.js';
import type { Queryable } from './database.js';
import { canonical, hash } from '../shared/authority.js';
import { ContentTypes, Operations, functionOperations, grantActive } from '../shared/custody.js';
import { pointerParts, setPointer } from '../shared/values.js';
import { fail } from './errors.js';
import { functionProgram, functionSources } from '../shared/functions.js';
import type { z } from 'zod';

interface SettingsRow { function_id: string; environment_id: string | null; version: number; approval: SettingsApproval; }

export class Functions {
  constructor(readonly resources: Resources, readonly origin: string) {
    resources.ownership.set('function', row => {
      const { publication, ...definition } = row.data;
      return definition;
    });
  }
  private definition(row: ResourceRow) {
    const { publication, ...definition } = row.data;
    return FunctionDefinition.parse(definition);
  }
  private async publication(row: ResourceRow) {
    if (!row.data.publication) return null;
    try {
      const value = await verifyFunction(row.data.publication as unknown as z.infer<typeof FunctionWrite>['publication']);
      return value.functionId === row.id && value.ownerId === row.owner_id &&
        canonical(value.definition) === canonical(this.definition(row)) ? value : null;
    } catch { return null; }
  }
  private async approved(row: ResourceRow, settings: SettingsRow) {
    const approval = settings.approval;
    return approval.functionId === row.id && approval.ownerId === row.owner_id && approval.revision === settings.version &&
      approval.environmentId === settings.environment_id && approval.definitionDigest === await hash(this.definition(row));
  }
  references(spec: FunctionSpec): string[] {
    return functionSources(spec).map(source => source.id);
  }
  async validateSource(actor: Actor, source: SourceReference) {
    const row = await this.resources.get(source.id);
    if (row.kind === 'variable' ? source.output !== undefined : row.kind !== 'connection' || source.output === undefined)
      fail(400, 'wrong_kind', 'Choose a variable, or a connection and one of its outputs.');
    await this.resources.authorization.requireResource(actor, row, 'use');
    if (row.kind === 'connection' && (!Array.isArray(row.data.outputs) || !row.data.outputs.includes(source.output!)))
      fail(400, 'invalid_input', 'Choose an output provided by this connection.');
  }
  async validate(actor: Actor, spec: HttpRequestInput) {
    if (spec.url) publicUrl(spec.url, this.origin);
    if (spec.connectionId) {
      const row = await this.resources.get(spec.connectionId);
      if (row.kind !== 'connection' || !row.data.http)
        fail(400, 'wrong_kind', 'Choose a connection that provides HTTP authentication.');
      await this.resources.authorization.requireResource(actor, row, 'use');
      if (!spec.url && !(row.data.http as Record<string, unknown>).urlField)
        fail(400, 'invalid_url', 'Enter a destination URL for this connection.');
    }
    if ([spec.body, spec.json, spec.form].filter(value => value !== undefined).length > 1)
      fail(400, 'multiple_bodies', 'Choose one request body format.');
    for (const binding of spec.bindings) {
      let parts: string[];
      try { parts = pointerParts(binding.pointer); setPointer(structuredClone(spec), binding.pointer, 'validation'); }
      catch { fail(400, 'invalid_binding', 'Choose a field in the headers or body.'); }
      if (!parts.length || !['headers', 'body', 'json', 'form'].includes(parts[0]!) ||
        (parts[0] === 'body' && parts.length !== 1) ||
        (['headers', 'form'].includes(parts[0]!) && parts.length !== 2))
        fail(400, 'invalid_binding', 'Choose a field in the headers or body.');
      for (const part of binding.parts) if (typeof part !== 'string') await this.validateSource(actor, part);
    }
  }
  async validateFunction(actor: Actor, definition: FunctionSpec) {
    const spec = FunctionDefinition.parse(definition), names = new Set<string>();
    for (const parameter of spec.parameters) {
      if (names.has(parameter.name)) fail(400, 'duplicate_parameter', 'Use unique parameter names.');
      names.add(parameter.name);
    }
    const example = Object.fromEntries(spec.parameters.map(parameter => [parameter.name, parameter.default !== undefined ? parameter.default
      : parameter.type === 'number' ? 0 : parameter.type === 'boolean' ? false : parameter.type === 'json' ? {} : 'example']));
    let program: ReturnType<typeof functionProgram>;
    try { program = functionProgram(spec, example); }
    catch { fail(400, 'invalid_input', 'Declare valid function parameters and matching default values.'); }
    if (program.kind === 'http') await this.validate(actor, program.request);
    else {
      if (!program.command[0]?.trim()) fail(400, 'invalid_command', 'Choose the program to execute.');
      if (new Set(program.inputs.map(input => input.name)).size !== program.inputs.length)
        fail(400, 'duplicate_input', 'Use unique input names.');
      for (const input of program.inputs) {
        if (!validInputName(input.name)) fail(400, 'invalid_input', 'Use an unreserved environment variable name.');
        if (input.pointer !== undefined) {
          try { pointerParts(input.pointer); }
          catch { fail(400, 'invalid_pointer', 'Use a valid JSON pointer for the input.'); }
        }
        await this.validateSource(actor, input.source);
      }
    }
    return spec;
  }
  async sources(spec: FunctionSpec, custody: Custody) {
    const sources = new Map<string, Awaited<ReturnType<Custody['get']>>>();
    for (const id of new Set(functionSources(spec).map(source => source.id))) sources.set(id, await custody.get(id));
    for (const source of [...sources.values()])
      if (source.policy.contentType === ContentTypes.tokenSet && typeof source.metadata.appId === 'string' && !sources.has(source.metadata.appId))
        sources.set(source.metadata.appId, await custody.get(source.metadata.appId));
    return [...sources.values()];
  }
  async authorizations(actor: Actor, id: string, custody: Custody) {
    const fn = await this.resources.get(id);
    if (fn.kind !== 'function') fail(400, 'wrong_kind', 'Choose a saved function.');
    await this.resources.authorization.requireResource(actor, fn, 'update');
    const rows = await this.resources.db.all<{ id: string }>(
      `SELECT resource_id AS id FROM resource_custody c WHERE EXISTS
       (SELECT 1 FROM jsonb_array_elements(c.content->'policy'->'grants') g WHERE g->'function'->>'id'=$1) ORDER BY resource_id`, [id]);
    return { items: await Promise.all(rows.map(row => custody.read(actor, row.id))), next: null };
  }
  async save(actor: Actor, input: z.infer<typeof FunctionSave>, proof: z.infer<typeof FunctionWrite>, custody: Custody) {
    const previous = input.resourceId ? await this.resources.get(input.resourceId) : null;
    if (previous) {
      await this.resources.authorization.requireResource(actor, previous, 'update');
      if (previous.kind !== 'function' || previous.owner_id !== input.ownerId || previous.id !== proof.functionId || previous.version !== input.version)
        fail(409, 'changed', 'Reload this function before saving.');
      if (previous.name !== input.name) await this.resources.authorization.requireResource(actor, previous, 'rename');
    } else if (input.version || !(await this.resources.authorization.canCreate(actor, input.ownerId, 'function')))
      fail(403, 'forbidden', 'You cannot create this function.');
    const spec = await this.validateFunction(actor, input.definition);
    await this.validateFunction({ id: input.ownerId }, spec);
    const publication = await verifyFunction(proof.publication);
    await custody.bindings.requireCurrent(publication.author);
    if (publication.author.principalId !== actor.id || publication.functionId !== proof.functionId ||
      publication.ownerId !== input.ownerId || publication.revision !== (previous?.version ?? 0) + 1 ||
      canonical(publication.definition) !== canonical(spec))
      fail(400, 'invalid_function_publication', 'Sign the current function definition.');
    const row = await this.resources.db.transaction(async connection => {
      const data = { ...spec, publication } as unknown as Record<string, JsonValue>;
      const row = previous ? await this.resources.update(previous, { name: input.name, data }, connection)
        : await this.resources.insert(input.ownerId, 'function', input.name, data, { id: proof.functionId }, connection);
      await this.resources.references(row.id, this.references(spec), connection);
      await this.resources.audit.record(input.ownerId, actor.id, 'function.save', row.id, {}, connection);
      return row;
    });
    return this.resources.view(actor, row);
  }
  private settingsRow(id: string, connection: Queryable = this.resources.db.pool) {
    return this.resources.db.one<SettingsRow>('SELECT * FROM function_settings WHERE function_id=$1', [id], connection);
  }
  async settings(actor: Actor, id: string) {
    const row = await this.resources.get(id);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a saved function.');
    await this.resources.authorization.requireResource(actor, row, 'read');
    const settings = await this.settingsRow(id), publication = await this.publication(row);
    let state: z.infer<typeof FunctionExecutionSettings>['state'] = publication ? 'unconfigured' : 'publication_required';
    if (publication && settings?.environment_id) {
      const environment = await this.resources.db.one<{ stopped_at: Date | null }>(
        'SELECT stopped_at FROM executor_environments WHERE resource_id=$1', [settings.environment_id]);
      state = !await this.approved(row, settings) ? 'approval_required'
        : !grantActive(settings.approval.inputAccess) ? 'expired'
          : !environment || environment.stopped_at ? 'unavailable' : 'configured';
    }
    return FunctionExecutionSettings.parse({ version: settings?.version ?? 0, environmentId: settings?.environment_id ?? null,
      inputAccess: settings?.approval.inputAccess ?? { expiresAt: null }, state });
  }
  async configure(actor: Actor, input: z.infer<typeof FunctionConfigure>, proof: z.infer<typeof FunctionSettingsWrite>,
    custody: Custody, delegation: Delegation) {
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [input.functionId]);
      const row = await this.resources.get(input.functionId, connection);
      if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a saved function.');
      await this.resources.authorization.requireResource(actor, row, 'update', connection);
      const previous = await this.settingsRow(row.id, connection);
      if (row.version !== input.functionVersion || (previous?.version ?? 0) !== input.version)
        fail(409, 'changed', 'Reload this function and its execution settings before saving.');
      const publication = await this.publication(row), spec = this.definition(row);
      const approval = await verifyFunctionSettings(proof.approval);
      await custody.bindings.requireCurrent(approval.author, connection);
      if (approval.author.principalId !== actor.id || approval.functionId !== row.id || approval.ownerId !== row.owner_id ||
        approval.revision !== input.version + 1 || approval.definitionDigest !== await hash(spec) ||
        approval.environmentId !== input.environmentId || canonical(approval.inputAccess) !== canonical(input.inputAccess))
        fail(400, 'invalid_function_settings', 'Approve the current function and its execution settings.');
      if (!grantActive(approval.inputAccess)) fail(400, 'invalid_input', 'Choose a future expiration for input access.');
      if (input.environmentId) {
        if (!publication) fail(409, 'function_not_published', 'Save the function to approve its current definition.');
        await this.validateFunction({ id: row.owner_id }, spec);
        await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [input.environmentId]);
        const environment = await delegation.environment(input.environmentId, connection);
        for (const who of [actor, { id: row.owner_id }])
          await this.resources.authorization.requireResource(who, await this.resources.get(input.environmentId, connection), 'execute', connection);
        if (environment.registration.manifest.functionVersion !== FUNCTION_RUNTIME_VERSION)
          fail(409, 'function_runtime_required', 'Update this execution environment to the current Foundation CLI.');
        if (environment.stopped_at || !environment.registration.manifest.capabilities.includes(Operations.function) ||
          !environment.registration.manifest.capabilities.includes(Operations[spec.program.kind]))
          fail(400, 'unsupported_environment', 'Choose an active environment that can execute this function.');
        if (spec.program.kind === 'http' && spec.program.request.connectionId && environment.registration.manifest.httpVersion !== HTTP_RUNTIME_VERSION)
          fail(409, 'http_runtime_required', 'Update this execution environment to use HTTP connections.');
        if (canonical(approval.executor) !== canonical(environment.registration.manifest.executor))
          fail(400, 'invalid_function_settings', 'Approve the selected execution environment.');
      }
      await this.approveInputs(actor, row.id, spec, approval, proof, custody, connection);
      await connection.query(`INSERT INTO function_settings(function_id,environment_id,version,approval) VALUES($1,$2,$3,$4)
        ON CONFLICT(function_id) DO UPDATE SET environment_id=$2,version=$3,approval=$4`,
        [row.id, input.environmentId, approval.revision, JSON.stringify(approval)]);
      await this.resources.audit.record(row.owner_id, actor.id, 'function.configure', row.id,
        { environmentId: input.environmentId }, connection);
      return this.resources.view(actor, row);
    });
  }
  private async approveInputs(actor: Actor, functionId: string, spec: FunctionSpec, approval: SettingsApproval,
    proof: z.infer<typeof FunctionSettingsWrite>, custody: Custody, connection: Queryable) {
    const sources = approval.environmentId ? await this.sources(spec, custody) : [], current = new Set(sources.map(source => source.policy.id));
    for (const item of (await this.authorizations(actor, functionId, custody)).items)
      if (!current.has(item.content.policy.id)) sources.push(item.content);
    const reference = { id: functionId, digest: approval.definitionDigest };
    if (Object.values(proof.contents).filter(item => current.has(item.content.policy.id))
      .reduce((bytes, item) => bytes + JSON.stringify(item.content).length, 0) > 16_000_000)
      fail(413, 'input_limit', 'Use at most 16 MB of encrypted inputs in one function.');
    if (canonical(Object.keys(proof.contents).sort()) !== canonical(sources.map(source => source.policy.id).sort()))
      fail(400, 'missing_inputs', 'Approve each input needed by this function.');
    for (const source of sources) {
      const content = proof.contents[source.policy.id]!.content;
      const operations = functionOperations(source.policy.contentType);
      const grants = content.policy.grants.filter(grant => 'function' in grant && grant.function.id === functionId);
      const granted = grants.length === 1 && grants.some(grant => 'function' in grant && canonical(grant.function) === canonical(reference) &&
        canonical(grant.executor) === canonical(approval.executor) && operations.every(operation => grant.operations.includes(operation)) &&
        grantActive(grant) && grant.expiresAt === approval.inputAccess.expiresAt);
      if ((current.has(source.policy.id) ? !granted : grants.length !== 0) ||
        canonical(content.metadata) !== canonical(source.metadata))
        fail(400, 'function_not_approved', 'Approve this exact function and execution environment for every input.');
    }
    for (const source of sources) await custody.put(actor, { name: (await this.resources.get(source.policy.id, connection)).name,
        ...proof.contents[source.policy.id]! }, connection);
  }
  async execution(actor: Actor, id: string, custody: Custody, delegation: Delegation, connection: Queryable = this.resources.db.pool) {
    const row = await this.resources.get(id, connection);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a saved function.');
    await this.resources.authorization.requireResource(actor, row, 'execute');
    const definition = this.definition(row), configured = await this.settingsRow(id, connection);
    const publication = await this.publication(row);
    if (!publication) fail(409, 'function_not_published', 'Save this function to approve its current definition.');
    if (!configured?.environment_id) fail(409, 'function_not_configured', 'The owner must configure this function’s execution environment.');
    const settings = await verifyFunctionSettings(configured.approval);
    if (!await this.approved(row, configured) || !grantActive(settings.inputAccess))
      fail(409, 'function_not_approved', 'The owner must approve this function’s execution settings again.');
    const environment = await delegation.environment(configured.environment_id, connection);
    if (environment.registration.manifest.functionVersion !== FUNCTION_RUNTIME_VERSION)
      fail(409, 'function_runtime_required', 'Update this execution environment to the current Foundation CLI.');
    if (environment.stopped_at) fail(409, 'environment_stopped', 'This function’s environment has stopped.');
    if (canonical(settings.executor) !== canonical(environment.registration.manifest.executor))
      fail(409, 'function_not_approved', 'The owner must approve this execution environment again.');
    await this.resources.authorization.requireResource({ id: row.owner_id }, await this.resources.get(configured.environment_id, connection), 'execute', connection);
    const sources = await this.sources(definition, custody), reference = { id, digest: await hash(definition) };
    for (const source of sources)
      if (!source.policy.grants.some(grant => 'function' in grant && canonical(grant.function) === canonical(reference) &&
        canonical(grant.executor) === canonical(settings.executor) &&
        functionOperations(source.policy.contentType).every(operation => grant.operations.includes(operation)) && grantActive(grant)))
        fail(409, 'function_not_approved', 'The owner must approve this function’s inputs again.');
    return { row, definition, publication, settings, registration: environment.registration, sources };
  }
}
