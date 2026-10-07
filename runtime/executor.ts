import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import { canonical, hash } from '../shared/authority.js';
import type { HttpRequestInput, JsonValue, SourceReference } from '../shared/contracts.js';
import {
  authorizeUse, matchesPin, openRun, produceContent, useContent, verifyContent, verifyPolicyApproval,
} from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent, SealedRun } from '../shared/custody.js';
import {
  RuntimeOperation, authorizeEnvironment, makeReceipt,
} from '../shared/execution.js';
import type { ExecutionOperation as Operation, RegisteredEnvironment, SignedReceipt, TaskView } from '../shared/execution.js';
import { functionRequest } from '../shared/function-request.js';
import { atPointer, pointerParts, redact, setPointer } from '../shared/values.js';
import { encode } from '../shared/encryption.js';
import type { Transport } from '../server/transport.js';
import { publicUrl } from '../server/transport.js';
import { DomainError } from '../server/errors.js';
import type { Journal } from './journal.js';
import type { CommandExecutor } from './command.js';
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
  outputs(content: CustodyContent, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<Record<string, string>>;
}
interface RunRecord {
  digest: string;
  lease: string;
  request: SealedRun;
  phase: 'prepared' | 'dispatched' | 'settled';
  receipt?: SignedReceipt;
  delivered: boolean;
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
  ) {}
  get binding(): BoundKeys { return this.environment.manifest.executor; }

  async reconcile() {
    for (const key of await this.journal.keys('run_')) {
      const record = await this.journal.read<RunRecord>(key);
      if (!record || record.delivered) continue;
      if (!record.receipt && record.phase === 'dispatched') {
        record.receipt = await makeReceipt(record.request.intent, 'uncertain', {
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
    }
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
      if (operation.kind !== intent.operation) throw new Error('Use the operation authorized by this intent.');
      await this.preflight(operation, intent, claim.sources);
      runningSignal.throwIfAborted();
      record.phase = 'dispatched';
      await this.journal.write(id, record);
      dispatched = true;
      await this.broker.dispatch(intent.id, claim.lease);
      runningSignal.throwIfAborted();
      const result = await this.execute(operation, intent, claim.sources, runningSignal);
      receipt = await makeReceipt(intent, 'succeeded', { ok: true, result, error: null }, this.keys);
    } catch (error) {
      const uncertain = dispatched && (runningSignal.aborted || !(error instanceof DomainError) ||
        ['service_unavailable', 'connection_uncertain', 'lease_lost'].includes(error.code));
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
    if (operation.kind === 'http') return operation.request;
    if (operation.kind === 'function') return functionRequest(operation.definition, operation.arguments);
    return null;
  }

  private async preflight(operation: Operation, intent: ExecutionIntent, sources: CustodyContent[]) {
    if (new Set(sources.map(source => source.policy.id)).size !== sources.length ||
      sources.length !== intent.sources.length) throw new Error('Supply exactly the signed execution inputs.');
    for (const source of sources) {
      await verifyContent(source);
      const pin = intent.sources.find(pin => pin.id === source.policy.id);
      if (!pin || !await matchesPin(source, pin))
        throw new Error('An execution input changed.');
      const checkpoint = await this.journal.read<{ policy: number; material: number }>('checkpoint_' + source.policy.id);
      if (checkpoint && (source.policy.revision < checkpoint.policy || source.materialRevision < checkpoint.material))
        throw new Error('The execution input is older than this executor has already observed.');
      await this.journal.write('checkpoint_' + source.policy.id,
        { policy: source.policy.revision, material: source.materialRevision });
    }
    if (operation.kind === 'function' && await hash(operation.definition) !== intent.functionDigest)
      throw new Error('Run the exact function authorized by this intent.');
    const request = this.request(operation);
    if (request) {
      publicUrl(request.url, intent.origin);
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
      const save = operation.kind === 'function' ? operation.outputs : operation.kind === 'http' ? operation.save : {};
      if (operation.kind === 'function') {
        if (Object.keys(save).length !== Object.keys(operation.definition.save).length ||
          Object.entries(operation.definition.save).some(([pointer, name]) => save[pointer]?.name !== name))
          throw new Error('Use the output destinations declared by this function.');
      }
      for (const [pointer, output] of Object.entries(save)) {
        pointerParts(pointer);
        if (!this.broker.capture) throw new Error('This executor cannot save encrypted outputs.');
        const approval = await verifyPolicyApproval(output.approval);
        if (canonical(approval.policy.authorities.find(authority => authority.id === approval.authorityId)) !== canonical(intent.actor) ||
          approval.policy.origin !== intent.origin ||
          approval.policy.kind !== 'secret' || approval.policy.ownerId !== intent.ownerId ||
          (operation.kind === 'function' && operation.definition.outputOwnerId !== approval.policy.ownerId) ||
          !approval.policy.producers.some(producer => producer.runId === intent.id &&
            canonical(producer.executor) === canonical(this.binding) && Date.parse(producer.expiresAt) > Date.now()))
          throw new Error('Approve each encrypted output for this execution.');
      }
    }
    const references = operation.kind === 'command' ? operation.inputs.map(input => input.source)
      : request ? request.bindings.flatMap(binding => binding.parts.filter((part): part is SourceReference => typeof part !== 'string')) : [];
    for (const source of references) {
      const content = sources.find(value => value.policy.id === source.id);
      if (!content || content.policy.kind !== source.kind) throw new Error('Use the input named in the signed request.');
      await authorizeUse(content, intent, { ...(request ? { destination: request.url } : {}) });
      await useContent(content, intent, this.keys, { ...(request ? { destination: request.url } : {}) });
    }
    if (operation.kind === 'connect' || operation.kind === 'refresh' || operation.kind === 'revoke') {
      if (!this.extension) throw new Error('This executor cannot manage connections.');
      await this.extension.validate(operation.input, intent, sources);
    }
  }

  private async execute(operation: Operation, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue> {
    if (operation.kind === 'connect' || operation.kind === 'refresh' || operation.kind === 'revoke')
      return this.extension!.execute(operation.input, intent, sources, signal);
    const request = this.request(operation);
    const sensitive: string[] = [], cache = new Map<string, Promise<Record<string, string>>>();
    const resolve = async (source: SourceReference) => {
      const content = sources.find(content => content.policy.id === source.id)!;
      if (source.kind === 'secret') return useContent(content, intent, this.keys, {
        ...(request ? { destination: request.url } : {}),
      });
      if (!this.extension) throw new Error('This executor cannot use connections.');
      if (!cache.has(source.id)) cache.set(source.id, this.extension.outputs(content, intent, sources, signal));
      const outputs = await cache.get(source.id)!;
      if (!Object.hasOwn(outputs, source.output)) throw new Error('Choose an available connection output.');
      return encode(outputs[source.output]!);
    };
    if (operation.kind === 'command') {
      const values = await processInputs(operation.inputs, resolve);
      const result = await this.commands.execute({ command: operation.command, timeoutSeconds: operation.timeoutSeconds,
        ...(operation.stdin === undefined ? {} : { stdin: operation.stdin }),
        environment: values.environment, files: values.files }, signal);
      return { ...result, stdout: redact(result.stdout, values.sensitive), stderr: redact(result.stderr, values.sensitive) };
    }
    const spec = structuredClone(request!);
    for (const binding of spec.bindings) {
      let value = '';
      for (const part of binding.parts) {
        if (typeof part === 'string') value += part;
        else {
          const text = utf8(await resolve(part));
          sensitive.push(text, Buffer.from(text).toString('base64'), Buffer.from(text).toString('base64url'));
          value += text;
        }
      }
      setPointer(spec, binding.pointer, value);
    }
    let body = spec.body;
    if (spec.json !== undefined) { body = JSON.stringify(spec.json); spec.headers['content-type'] = 'application/json'; }
    if (spec.form !== undefined) { body = new URLSearchParams(spec.form).toString(); spec.headers['content-type'] = 'application/x-www-form-urlencoded'; }
    const response = await this.transport.send({ url: spec.url, method: spec.method, headers: spec.headers,
      ...(body === undefined ? {} : { body }), signal });
    const save = operation.kind === 'function' ? operation.outputs : operation.kind === 'http' ? operation.save : {};
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
}
