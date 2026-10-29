import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import { canonical, hash } from '../shared/authority.js';
import { Json } from '../shared/contracts.js';
import type { HttpRequestInput, JsonValue, SourceReference } from '../shared/contracts.js';
import {
  ContentTypes, Operations, authorizeUse, matchesPin, openRun, produceContent, useContent, verifyContent, verifyPolicyApproval,
} from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent, SealedRun } from '../shared/custody.js';
import {
  HTTP_RUNTIME_VERSION, ResultTooLarge, RuntimeOperation, authorizeEnvironment, makeReceipt,
} from '../shared/runtime-protocol.js';
import type { ExecutableOperation as Operation, RegisteredEnvironment, SignedReceipt, TaskView } from '../shared/runtime-protocol.js';
import { functionProgram } from '../shared/functions.js';
import { httpSources } from '../shared/http-connections.js';
import { authorizeOperationContext } from '../shared/operation-authorization.js';
import { atPointer, pointerParts, redact, setPointer } from '../shared/values.js';
import { encode } from '../shared/encryption.js';
import type { Transport } from '../server/transport.js';
import { publicUrl } from '../server/transport.js';
import { DomainError } from '../server/errors.js';
import type { Journal } from './journal.js';
import type { CommandExecutor } from './command.js';
import type { ConnectionOutputs } from './connection-provider.js';
import { processInputs, utf8 } from './inputs.js';

export interface ExecutionBroker {
  claim(environmentId: string): Promise<{ lease: string; request: SealedRun; sources: CustodyContent[] } | null>;
  renew(id: string, lease: string): Promise<{ active: boolean }>;
  dispatch(id: string, lease: string): Promise<unknown>;
  finish(lease: string, receipt: SignedReceipt): Promise<TaskView>;
  capture?(name: string, content: CustodyContent): Promise<{ id: string }>;
}
export interface ExecutionExtension {
  validate(operation: JsonValue, intent: ExecutionIntent, sources: CustodyContent[]): Promise<void>;
  execute(operation: JsonValue, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue>;
  outputs(content: CustodyContent, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal, destination?: string): Promise<ConnectionOutputs>;
  httpDestination?(content: CustodyContent, intent: ExecutionIntent, request: HttpRequestInput): Promise<string>;
  http?(content: CustodyContent, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal,
    request: HttpRequestInput): Promise<{ url: string; headers: Record<string, string>; sensitive: string[] }>;
  recover?(operation: JsonValue, intent: ExecutionIntent): Promise<JsonValue | null>;
}
// A variable is used whole; a connection is used through one of its named outputs.
function fits(content: CustodyContent, source: SourceReference) {
  if (content.policy.contentType === ContentTypes.value) return source.output === undefined;
  return content.policy.contentType === ContentTypes.tokenSet && source.output !== undefined;
}
export class DeliveryPending extends Error {
  constructor() { super('A completed result is waiting for delivery. Restart or leave this executor running to reconcile it.'); }
}
export function executionUncertain(error: unknown) {
  return !(error instanceof DomainError) || ['service_unavailable', 'connection_uncertain', 'lease_lost'].includes(error.code);
}
interface RunRecord {
  digest: string;
  lease: string;
  request: SealedRun;
  phase: 'prepared' | 'dispatched' | 'settled';
  receipt?: SignedReceipt;
  delivered: boolean;
  operation?: Operation;
}

export class Executor {
  constructor(
    readonly environment: RegisteredEnvironment,
    readonly keys: IdentityKeys,
    readonly broker: ExecutionBroker,
    readonly journal: Journal,
    readonly transport: Transport,
    readonly commands: CommandExecutor,
    readonly extension?: ExecutionExtension,
    readonly functionCommands: CommandExecutor = commands,
  ) {}
  get binding(): BoundKeys { return this.environment.manifest.executor; }

  async reconcile() {
    const pending: string[] = [];
    for (const key of await this.journal.pending('run_')) {
      try {
      const record = await this.journal.read<RunRecord>(key);
      if (!record || record.delivered) continue;
      if (!record.receipt && record.phase === 'dispatched') {
        const recovered = record.operation?.kind === 'connect'
          ? await this.extension?.recover?.(record.operation.input, record.request.intent) : null;
        record.receipt = recovered ? await makeReceipt(record.request.intent, 'succeeded', {
          ok: true, result: recovered, error: null,
        }, this.keys) : await makeReceipt(record.request.intent, 'uncertain', {
          ok: false, result: null,
          error: { code: 'execution_interrupted', message: 'Check the destination before starting another operation.' },
        }, this.keys);
        record.phase = 'settled';
        await this.journal.write(key, record);
      }
      if (record.receipt) {
        await this.broker.finish(record.lease, record.receipt);
        record.delivered = true;
        await this.journal.write(key, record);
      }
      } catch { pending.push(key.slice(4)); }
    }
    return pending;
  }

  async tick(signal: AbortSignal = new AbortController().signal) {
    signal.throwIfAborted();
    const claim = await this.broker.claim(this.environment.manifest.id);
    if (!claim) return false;
    const { intent } = claim.request;
    const id = 'run_' + intent.id, digest = await hash(claim.request);
    let record = await this.journal.read<RunRecord>(id);
    if (record && record.digest !== digest) throw new Error('A run ID was reused for a different signed request.');
    if (record?.receipt) {
      await this.broker.finish(claim.lease, record.receipt);
      await this.journal.write(id, { ...record, delivered: true });
      return true;
    }
    if (record?.phase === 'dispatched') {
      const receipt = await makeReceipt(intent, 'uncertain', { ok: false, result: null,
        error: { code: 'execution_interrupted', message: 'Check the destination before starting another operation.' } }, this.keys);
      await this.journal.write(id, { ...record, lease: claim.lease, phase: 'settled', receipt, delivered: false });
      await this.broker.finish(claim.lease, receipt);
      return true;
    }
    record = { digest, lease: claim.lease, request: claim.request, phase: 'prepared', delivered: false };
    await this.journal.write(id, record);
    const controller = new AbortController();
    const runningSignal = AbortSignal.any([signal, controller.signal]);
    const heartbeat = setInterval(() => {
      void this.broker.renew(intent.id, claim.lease).then(result => {
        if (!result.active) controller.abort();
      }).catch(() => controller.abort());
    }, 15_000);
    heartbeat.unref();
    let dispatched = false;
    let receipt: SignedReceipt;
    try {
      const opened = await openRun(claim.request, this.binding, this.keys);
      await authorizeEnvironment(this.environment, opened.intent);
      const operation = RuntimeOperation.parse(opened.operation);
      if (Operations[operation.kind] !== intent.operation) throw new Error('Use the operation authorized by this intent.');
      await authorizeOperationContext(intent, operation);
      await this.validateOperation(operation, intent, claim.sources);
      runningSignal.throwIfAborted();
      record.operation = operation;
      record.phase = 'dispatched';
      await this.journal.write(id, record);
      dispatched = true;
      await this.broker.dispatch(intent.id, claim.lease);
      runningSignal.throwIfAborted();
      const result = await this.executeOperation(operation, intent, claim.sources, runningSignal);
      receipt = await makeReceipt(intent, 'succeeded', { ok: true, result, error: null }, this.keys);
    } catch (error) {
      if (error instanceof DeliveryPending) throw error;
      if (error instanceof ResultTooLarge) error = new DomainError(413, 'result_too_large',
        'The operation completed, but its result is too large to return. Check the destination before starting it again.');
      const uncertain = dispatched && (runningSignal.aborted || executionUncertain(error));
      receipt = await makeReceipt(intent, uncertain ? 'uncertain' : 'failed', {
        ok: false, result: null,
        error: error instanceof DomainError
          ? { code: error.code, message: error.message }
          : { code: uncertain ? 'execution_uncertain' : 'invalid_execution',
              message: uncertain ? 'Check the destination before starting another operation.' : 'The executor could not authorize this operation.' },
      }, this.keys);
    } finally { clearInterval(heartbeat); }
    record.phase = 'settled';
    record.receipt = receipt;
    await this.journal.write(id, record);
    await this.broker.finish(claim.lease, receipt);
    record.delivered = true;
    await this.journal.write(id, record);
    return true;
  }

  private request(operation: Operation): HttpRequestInput | null {
    const program = operation.kind === 'function' ? functionProgram(operation.definition, operation.arguments) : operation;
    return program.kind === 'http' ? program.request : null;
  }

  async validateOperation(operation: Operation, intent: ExecutionIntent, sources: CustodyContent[]) {
    if (new Set(sources.map(source => source.policy.id)).size !== sources.length ||
      sources.length !== intent.sources.length) throw new Error('Supply exactly the signed execution inputs.');
    for (const source of sources) {
      await verifyContent(source);
      const pin = intent.sources.find(pin => pin.id === source.policy.id);
      if (!pin || !await matchesPin(source, pin))
        throw new Error('An execution input changed.');
      const checkpointId = 'checkpoint_' + source.policy.format + '_' + source.policy.id;
      const checkpoint = await this.journal.read<{ policy: number; material: number }>(checkpointId);
      if (checkpoint && (source.policy.revision < checkpoint.policy || source.materialRevision < checkpoint.material))
        throw new Error('The execution input is older than this executor has already observed.');
      await this.journal.write(checkpointId,
        { policy: source.policy.revision, material: source.materialRevision });
    }
    if (operation.kind === 'function' && (operation.functionId !== intent.functionId ||
      await hash(operation.definition) !== intent.functionDigest ||
      !this.environment.manifest.capabilities.includes(Operations[operation.definition.program.kind])))
      throw new Error('Run the exact function authorized by this intent.');
    if (operation.kind !== 'function' && (intent.functionId || intent.functionDigest)) throw new Error('Use function authorization only for a saved function.');
    const request = this.request(operation);
    let destination = request?.url;
    if (request) {
      if (request.connectionId) {
        const content = sources.find(value => value.policy.id === request.connectionId);
        if (this.environment.manifest.httpVersion !== HTTP_RUNTIME_VERSION || !this.extension?.httpDestination ||
          !content || content.policy.contentType !== ContentTypes.tokenSet)
          throw new Error('Choose an HTTP connection and a current execution environment.');
        destination = await this.extension.httpDestination(content, intent, request);
      }
      publicUrl(destination!, intent.origin);
      if ([request.body, request.json, request.form].filter(value => value !== undefined).length > 1)
        throw new Error('Choose one request body format.');
      for (const binding of request.bindings) {
        const parts = pointerParts(binding.pointer);
        if (!parts.length || !['headers', 'body', 'json', 'form'].includes(parts[0]!) ||
          (parts[0] === 'body' && parts.length !== 1) ||
          (['headers', 'form'].includes(parts[0]!) && parts.length !== 2))
          throw new Error('Bind credentials to request headers or the body.');
        setPointer(structuredClone(request), binding.pointer, 'validation');
      }
    }
    const save = operation.kind === 'function' ? operation.outputs : operation.kind === 'http' ? operation.save : {};
    for (const [pointer, output] of Object.entries(save)) {
      pointerParts(pointer);
      if (!this.broker.capture) throw new Error('This executor cannot save encrypted outputs.');
      const approval = await verifyPolicyApproval(output.approval);
      if (canonical(approval.policy.authorities.find(authority => authority.id === approval.authorityId)) !== canonical(intent.actor) ||
        approval.policy.origin !== intent.origin ||
        approval.policy.contentType !== ContentTypes.value || approval.policy.ownerId !== intent.ownerId ||
        !approval.policy.producers.some(producer => producer.runId === intent.id &&
          canonical(producer.executor) === canonical(this.binding) && Date.parse(producer.expiresAt) > Date.now()))
        throw new Error('Approve each encrypted output for this execution.');
    }
    const program = operation.kind === 'function' ? functionProgram(operation.definition, operation.arguments) : operation;
    const references = program.kind === 'command' ? program.inputs.map(input => input.source)
      : request ? httpSources(request) : [];
    for (const source of references) {
      const content = sources.find(value => value.policy.id === source.id);
      const connection = request?.connectionId === source.id && source.output === undefined;
      if (!content || !(connection ? content.policy.contentType === ContentTypes.tokenSet : fits(content, source)))
        throw new Error('Use the input named in the signed request.');
      await authorizeUse(content, intent, { destination });
      await useContent(content, intent, this.keys, { destination });
    }
    if (operation.kind === 'connect' || operation.kind === 'refresh' || operation.kind === 'revoke') {
      if (!this.extension) throw new Error('This executor cannot manage connections.');
      await this.extension.validate(operation.input, intent, sources);
    }
  }

  async executeOperation(operation: Operation, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue> {
    if (operation.kind === 'connect' || operation.kind === 'refresh' || operation.kind === 'revoke')
      return this.extension!.execute(operation.input, intent, sources, signal);
    const request = this.request(operation);
    const program = operation.kind === 'function' ? functionProgram(operation.definition, operation.arguments) : operation;
    const destination = request?.connectionId
      ? await this.extension!.httpDestination!(sources.find(content => content.policy.id === request.connectionId)!, intent, request)
      : request?.url;
    const sensitive: string[] = [], cache = new Map<string, Promise<ConnectionOutputs>>();
    const resolve = async (source: SourceReference) => {
      const content = sources.find(content => content.policy.id === source.id)!;
      if (content.policy.contentType === ContentTypes.value) return { value: await useContent(content, intent, this.keys, {
        ...(request ? { destination } : {}),
      }) };
      if (!this.extension) throw new Error('This executor cannot use connections.');
      if (!cache.has(source.id)) cache.set(source.id, this.extension.outputs(content, intent, sources, signal, destination));
      const { values, files } = await cache.get(source.id)!;
      if (!source.output || !Object.hasOwn(values, source.output)) throw new Error('Choose an available connection output.');
      return { value: encode(values[source.output]!), file: files.includes(source.output) };
    };
    if (program.kind === 'command') {
      const values = await processInputs(program.inputs, resolve);
      const commands = operation.kind === 'function' ? this.functionCommands : this.commands;
      const result = await commands.execute({ command: program.command, timeoutSeconds: program.timeoutSeconds,
        ...(program.stdin === undefined ? {} : { stdin: program.stdin }),
        environment: values.environment, files: values.files,
        ...(operation.kind === 'function' ? { workspace: 'temporary' as const } : {}) }, signal);
      if (operation.kind === 'function') {
        if (result.timedOut) throw new DomainError(408, 'function_timeout', 'The function exceeded its time limit.');
        if (result.truncated) throw new DomainError(413, 'function_output_limit', 'The function output exceeded its size limit.');
        if (result.exitCode !== 0) throw new DomainError(422, 'function_failed', redact(result.stderr, values.sensitive).slice(0, 1000) || 'The function did not finish successfully.');
        return this.functionResult(operation, intent, result.stdout);
      }
      return { ...result, stdout: redact(result.stdout, values.sensitive), stderr: redact(result.stderr, values.sensitive) };
    }
    const spec = structuredClone(request!);
    for (const binding of spec.bindings) {
      let value = '';
      for (const part of binding.parts) {
        if (typeof part === 'string') value += part;
        else {
          const text = utf8((await resolve(part)).value);
          sensitive.push(text, Buffer.from(text).toString('base64'), Buffer.from(text).toString('base64url'));
          value += text;
        }
      }
      setPointer(spec, binding.pointer, value);
    }
    if (spec.connectionId) {
      if (!this.extension?.http) throw new Error('This executor cannot use HTTP connections.');
      const authenticated = await this.extension.http(sources.find(content => content.policy.id === spec.connectionId)!,
        intent, sources, signal, spec);
      spec.url = authenticated.url;
      spec.headers = authenticated.headers;
      sensitive.push(...authenticated.sensitive);
    }
    let body = spec.body;
    if (spec.json !== undefined) { body = JSON.stringify(spec.json); spec.headers['content-type'] = 'application/json'; }
    if (spec.form !== undefined) { body = new URLSearchParams(spec.form).toString(); spec.headers['content-type'] = 'application/x-www-form-urlencoded'; }
    const response = await this.transport.send({ url: spec.url!, method: spec.method, headers: spec.headers,
      ...(body === undefined ? {} : { body }), signal });
    if (operation.kind === 'function') {
      if (response.status < 200 || response.status >= 300)
        throw new DomainError(502, 'service_response', 'The service returned HTTP ' + response.status + '.');
      const format = operation.definition.program.kind === 'http' ? operation.definition.program.responseFormat : 'json';
      let body: JsonValue = utf8(response.body);
      if (format === 'json') {
        try { body = response.body.length === 0 && ([204, 205].includes(response.status) || spec.method === 'HEAD') ? null : Json.parse(JSON.parse(body)); }
        catch { throw new DomainError(422, 'invalid_function_result', 'The HTTP response body must contain valid JSON.'); }
      }
      return this.functionResult(operation, intent, JSON.stringify({ status: response.status, headers: response.headers, body }));
    }
    const save = operation.kind === 'http' ? operation.save : {};
    if (Object.keys(save).length) {
      if (response.status >= 400) throw new DomainError(502, 'service_response', 'The service returned an unsuccessful response.');
      const saved: Record<string, string> = {};
      for (const [pointer, destination] of Object.entries(save)) {
        let bytes = response.body;
        if (pointer !== '') {
          const value = atPointer(JSON.parse(utf8(bytes)), pointer);
          if (value === undefined) throw new DomainError(400, 'invalid_pointer', 'The response value was not found.');
          bytes = encode(typeof value === 'string' ? value : JSON.stringify(value));
        }
        const content = await produceContent(bytes, destination.approval, intent.id, this.binding, this.keys, { bytes: bytes.length });
        saved[destination.name] = (await this.broker.capture!(destination.name, content)).id;
      }
      return { status: response.status, saved };
    }
    return { status: response.status, headers: Object.fromEntries(Object.entries(response.headers)
      .map(([key, value]) => [key, redact(value, sensitive)])), body: redact(utf8(response.body), sensitive) };
  }
  private async functionResult(operation: Extract<Operation, { kind: 'function' }>, intent: ExecutionIntent, text: string): Promise<JsonValue> {
    let value: JsonValue;
    try { value = operation.definition.result === 'text' ? text : Json.parse(JSON.parse(text)); }
    catch { throw new DomainError(422, 'invalid_function_result', 'The function must return valid JSON.'); }
    const saved: Record<string, string> = {};
    for (const [pointer, destination] of Object.entries(operation.outputs)) {
      const selected = pointer === '' ? value : atPointer(value, pointer);
      if (selected === undefined) throw new DomainError(400, 'invalid_pointer', 'The function result value was not found.');
      const bytes = encode(typeof selected === 'string' ? selected : JSON.stringify(selected));
      const content = await produceContent(bytes, destination.approval, intent.id, this.binding, this.keys, { bytes: bytes.length });
      saved[destination.name] = (await this.broker.capture!(destination.name, content)).id;
    }
    return Object.keys(saved).length ? { saved } : value;
  }
}
