import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import type { Custody } from './custody.js';
import type { Delegation } from './delegation.js';
import { publicUrl } from './transport.js';
import { FunctionDefinition, validInputName } from '../shared/contracts.js';
import type { FunctionSpec, HttpRequestInput, JsonValue, SourceReference } from '../shared/contracts.js';
import { FunctionSave } from '../shared/operations.js';
import { FunctionWrite, verifyFunction } from '../shared/function-api.js';
import { canonical, hash } from '../shared/authority.js';
import { ContentTypes, Operations, functionOperations } from '../shared/custody.js';
import { pointerParts, setPointer } from '../shared/values.js';
import { fail } from './errors.js';
import { functionProgram, functionSources } from '../shared/functions.js';
import type { z } from 'zod';

export class Functions {
  constructor(readonly resources: Resources, readonly origin: string) {}
  references(spec: FunctionSpec): string[] {
    return [spec.environmentId, ...functionSources(spec).map(source => source.id)];
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
    publicUrl(spec.url, this.origin);
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
  async validateFunction(actor: Actor, definition: FunctionSpec, delegation: Delegation) {
    const spec = FunctionDefinition.parse(definition), names = new Set<string>();
    for (const parameter of spec.parameters) {
      if (names.has(parameter.name)) fail(400, 'duplicate_parameter', 'Use unique parameter names.');
      names.add(parameter.name);
    }
    const environment = await delegation.environment(spec.environmentId);
    await this.resources.authorization.requireResource(actor, await this.resources.get(spec.environmentId), 'execute');
    if (environment.registration.manifest.functionVersion !== 2)
      fail(409, 'function_runtime_required', 'Update this environment to Foundation CLI 6 or create a new environment.');
    if (environment.stopped_at || !environment.registration.manifest.capabilities.includes(Operations.function) ||
      !environment.registration.manifest.capabilities.includes(Operations[spec.program.kind]))
      fail(400, 'unsupported_environment', 'Choose an active environment that can execute this function.');
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
  async save(actor: Actor, input: z.infer<typeof FunctionSave>, proof: z.infer<typeof FunctionWrite>, custody: Custody, delegation: Delegation) {
    const previous = input.resourceId ? await this.resources.get(input.resourceId) : null;
    if (previous) {
      await this.resources.authorization.requireResource(actor, previous, 'update');
      if (previous.kind !== 'function' || previous.owner_id !== input.ownerId || previous.id !== proof.functionId || previous.version !== input.version)
        fail(409, 'changed', 'Reload this function before saving.');
      if (previous.name !== input.name) await this.resources.authorization.requireResource(actor, previous, 'rename');
    } else if (input.version || !(await this.resources.authorization.canCreate(actor, input.ownerId, 'function')))
      fail(403, 'forbidden', 'You cannot create this function.');
    const spec = await this.validateFunction(actor, input.definition, delegation);
    await this.validateFunction({ id: input.ownerId }, spec, delegation);
    const publication = await verifyFunction(proof.publication);
    const executor = (await delegation.environment(spec.environmentId)).registration.manifest.executor;
    await custody.bindings.requireCurrent(publication.author);
    if (publication.author.principalId !== actor.id || publication.functionId !== proof.functionId ||
      publication.ownerId !== input.ownerId || publication.revision !== (previous?.version ?? 0) + 1 ||
      canonical(publication.definition) !== canonical(spec) || canonical(publication.executor) !== canonical(executor))
      fail(400, 'invalid_function_publication', 'Sign the current function definition and its selected execution environment.');
    const sources = await this.sources(spec, custody), current = new Set(sources.map(source => source.policy.id));
    if (previous) for (const item of (await this.authorizations(actor, previous.id, custody)).items)
      if (!current.has(item.content.policy.id)) sources.push(item.content);
    const reference = { id: proof.functionId, digest: await hash(spec) };
    if (Object.values(proof.contents).filter(item => current.has(item.content.policy.id))
      .reduce((bytes, item) => bytes + JSON.stringify(item.content).length, 0) > 16_000_000)
      fail(413, 'input_limit', 'Use at most 16 MB of encrypted inputs in one function.');
    if (canonical(Object.keys(proof.contents).sort()) !== canonical(sources.map(source => source.policy.id).sort()))
      fail(400, 'missing_inputs', 'Approve each input needed by this function.');
    for (const source of sources) {
      const content = proof.contents[source.policy.id]!.content;
      const operations = functionOperations(source.policy.contentType);
      const granted = content.policy.grants.some(grant => 'function' in grant && canonical(grant.function) === canonical(reference) &&
        canonical(grant.executor) === canonical(executor) && operations.every(operation => grant.operations.includes(operation)) &&
        Date.parse(grant.expiresAt) > Date.now());
      if ((current.has(source.policy.id) ? !granted : content.policy.grants.some(grant => 'function' in grant && grant.function.id === proof.functionId)) ||
        canonical(content.metadata) !== canonical(source.metadata))
        fail(400, 'function_not_approved', 'Approve this exact function and execution environment for every input.');
    }
    const row = await this.resources.db.transaction(async connection => {
      const data = { ...spec, publication } as unknown as Record<string, JsonValue>;
      const row = previous ? await this.resources.update(previous, { name: input.name, data }, connection)
        : await this.resources.insert(input.ownerId, 'function', input.name, data, { id: proof.functionId }, connection);
      await this.resources.references(row.id, this.references(spec), connection);
      for (const source of sources) await custody.put(actor, { name: (await this.resources.get(source.policy.id, connection)).name,
        ...proof.contents[source.policy.id]! }, connection);
      await this.resources.audit.record(input.ownerId, actor.id, 'function.save', row.id, { environmentId: spec.environmentId }, connection);
      return row;
    });
    return this.resources.view(actor, row);
  }
  async execution(actor: Actor, id: string, custody: Custody, delegation: Delegation) {
    const row = await this.resources.get(id);
    if (row.kind !== 'function') fail(400, 'wrong_kind', 'Choose a saved function.');
    await this.resources.authorization.requireResource(actor, row, 'execute');
    const { publication: storedPublication, ...storedDefinition } = row.data;
    const definition = FunctionDefinition.parse(storedDefinition), environment = await delegation.environment(definition.environmentId);
    if (environment.registration.manifest.functionVersion !== 2)
      fail(409, 'function_runtime_required', 'Update the execution environment to Foundation CLI 6.');
    if (!storedPublication) fail(409, 'function_not_published', 'Save this function to approve its current definition.');
    const publication = await verifyFunction(storedPublication as unknown as z.infer<typeof FunctionWrite>['publication']);
    if (canonical(publication.definition) !== canonical(definition) || publication.functionId !== row.id ||
      publication.ownerId !== row.owner_id || canonical(publication.executor) !== canonical(environment.registration.manifest.executor))
      fail(409, 'function_changed', 'Save this function to approve its current definition.');
    if (environment.stopped_at) fail(409, 'environment_stopped', 'This function’s environment has stopped.');
    await this.resources.authorization.requireResource({ id: row.owner_id }, await this.resources.get(definition.environmentId), 'execute');
    const sources = await this.sources(definition, custody), reference = { id, digest: await hash(definition) };
    for (const source of sources)
      if (!source.policy.grants.some(grant => 'function' in grant && canonical(grant.function) === canonical(reference) &&
        canonical(grant.executor) === canonical(environment.registration.manifest.executor) &&
        functionOperations(source.policy.contentType).every(operation => grant.operations.includes(operation)) && Date.parse(grant.expiresAt) > Date.now()))
        fail(409, 'function_not_approved', 'The owner must approve this function’s inputs again.');
    return { row, definition, publication, registration: environment.registration, sources };
  }
}
