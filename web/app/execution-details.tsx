import { z } from 'zod';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { JsonValue, ResourceView } from '../../shared/contracts';
import type { DefinitionCall, ExecutionView } from '../../shared/executions';
import { Invocation } from '../../shared/function-api';
import { canonical, hash } from '../../shared/authority';
import { PrivateProgram, reviewedProgram } from '../../shared/operation-authorization';
import { SealedContinuationStore } from '../../shared/operation-continuations';
import { Task } from '../../shared/runtime-protocol';
import type { RunKindName } from '../../shared/runtime-protocol';
import { api, errorCode } from './api';
import { custodyClient } from './custody';
import { resourcePath } from './navigation';
import { Button } from './components/ui/button';
import { DateText, Detail, ErrorNotice, JsonView, Notice } from './components';

type Output = { state: 'available'; value: JsonValue; kind: RunKindName } |
  { state: 'locked' } | { state: 'notShared' } | { state: 'unrecorded' } | { state: 'unavailable'; error?: string } | { state: 'failed'; error: string };
export type StepDetails = {
  startedAt: string | null; finishedAt: string | null; environmentId: string | null;
  program: z.infer<typeof PrivateProgram>['operation'] | null;
  connection?: ResourceView | null;
  output: Output | null;
};
const terminal = ['succeeded', 'failed', 'uncertain', 'cancelled'];

export async function loadExecutionDetails(item: ExecutionView, canReadOutput: boolean, signal: AbortSignal) {
  const steps = await Promise.all(item.steps.map(async step => {
    const operation = item.operations[step.index]!, reference = step.runs.at(-1);
    const details: StepDetails = { startedAt: null, finishedAt: null,
      environmentId: typeof operation.input.environmentId === 'string' ? operation.input.environmentId : null,
      program: null, output: null };
    if (!reference) return details;
    try {
      if (reference.kind === 'function') {
        const invocation = await api('/runtime/functions/' + reference.id, { signal }, Invocation);
        details.startedAt = invocation.startedAt; details.finishedAt = invocation.finishedAt;
        return details;
      }
      const task = await api('/runtime/runs/' + reference.id, { signal }, Task);
      details.startedAt = task.startedAt; details.finishedAt = task.finishedAt; details.environmentId = task.environmentId;
      if (!terminal.includes(task.state)) return details;
      if (!task.receipt) {
        details.output = task.error && task.state === 'failed' ? { state: 'failed', error: task.error } : { state: 'unrecorded' };
        return details;
      }
      if (!canReadOutput) { details.output = { state: 'locked' }; return details; }
      const custody = await custodyClient();
      const readers = 'content' in task.receipt ? task.receipt.content.policy.readers : task.intent.resultRecipients;
      if (!readers.some(reader => canonical(reader) === canonical(custody.binding))) {
        details.output = { state: 'notShared' }; return details;
      }
      const result = await custody.result(task);
      details.output = result?.ok ? { state: 'available', value: result.result, kind: task.kind }
        : result?.error ? { state: 'failed', error: result.error.code } : { state: 'unrecorded' };
      const input = operation.input.operation;
      if (canonical(custody.binding) === canonical(task.intent.actor) &&
        input && typeof input === 'object' && !Array.isArray(input) && typeof input.programId === 'string') {
        const program = await new SealedContinuationStore(custody).get(input.programId, PrivateProgram);
        if (program && await hash(reviewedProgram(program.operation)) === input.programDigest) details.program = program.operation;
        if (details.program?.kind === 'http' && details.program.request.connectionId) {
          try { details.connection = await api('/resources/' + details.program.request.connectionId, { signal }, Resource); }
          catch (error) { if (signal.aborted) throw error; }
        }
      }
    } catch (error) {
      if (signal.aborted) throw error;
      if (!details.output && terminal.includes(step.state)) {
        const code = errorCode(error);
        details.output = code === 'key_locked' ? { state: 'locked' } : { state: 'unavailable', error: code };
      }
    }
    return details;
  }));
  const ids = [...new Set(steps.flatMap(step => step.environmentId ? [step.environmentId] : []))];
  const environments = await Promise.all(ids.map(async id => {
    try { return await api('/resources/' + id, { signal }, Resource); }
    catch (error) { if (signal.aborted) throw error; return null; }
  }));
  let initiator = item.creator;
  if (item.actorId !== initiator.id) {
    try { initiator = await api('/principals/' + item.actorId, { signal }, Principal); }
    catch (error) { if (signal.aborted) throw error; initiator = { id: item.actorId, name: item.actorId }; }
  }
  return { steps, environments: environments.filter((item): item is ResourceView => item !== null), initiator };
}

export function executionTitle(operation: ExecutionView['operations'][number], language: string) {
  const input = operation.input.operation;
  const kind = input && typeof input === 'object' && !Array.isArray(input) ? input.kind : null;
  if (operation.name === 'run.execute' && kind === 'command') return language === 'ja' ? 'コマンドの実行' : 'Command execution';
  if (operation.name === 'run.execute' && kind === 'http') return language === 'ja' ? 'HTTPリクエスト' : 'HTTP request';
  return language === 'ja' ? operation.title.ja : operation.title.en;
}

export function ExecutionFacts({ details, environments }: { details: StepDetails; environments: ResourceView[] }) {
  const { t, i18n } = useTranslation(), environment = environments.find(item => item.id === details.environmentId);
  const duration = details.startedAt && details.finishedAt ? Math.max(0, (Date.parse(details.finishedAt) - Date.parse(details.startedAt)) / 1000) : null;
  return <>
    {details.environmentId && <Detail label={t('executionDestination')}>
      {environment ? <Link className="underline underline-offset-4" to={resourcePath(environment)}>{environment.name}</Link> : details.environmentId}
    </Detail>}
    {details.program?.kind === 'command' && <Detail label={t('command')}><code className="text-sm whitespace-pre-wrap wrap-anywhere">{details.program.command.map(value => /^[\w./:=+-]+$/.test(value) ? value : JSON.stringify(value)).join(' ')}</code></Detail>}
    {details.program?.kind === 'http' && <Detail label={t('http')}>{details.program.request.method} {details.program.request.url}</Detail>}
    {details.program?.kind === 'http' && details.program.request.connectionId && <Detail label={t('connection')}>
      {details.connection ? <Link className="underline underline-offset-4" to={resourcePath(details.connection)}>{details.connection.name}</Link>
        : details.program.request.connectionId}
    </Detail>}
    {details.startedAt && <Detail label={t('executionStarted')}><DateText value={details.startedAt} seconds /></Detail>}
    {details.finishedAt && <Detail label={t('executionFinished')}><DateText value={details.finishedAt} seconds /></Detail>}
    {duration !== null && <Detail label={t('executionDuration')}>{t('executionSeconds', { value: new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 3 }).format(duration) })}</Detail>}
  </>;
}

const CommandResult = z.object({ stdout: z.string(), stderr: z.string(), exitCode: z.number().int().nullable(),
  signal: z.string().nullable(), timedOut: z.boolean(), truncated: z.boolean() });
const HttpResult = z.object({ status: z.number().int(), body: z.string() });

function OutputText({ text }: { text: string }) {
  return <pre className="m-0 max-h-[480px] overflow-auto rounded-lg border bg-background/60 p-4 font-mono text-sm leading-relaxed whitespace-pre-wrap wrap-anywhere">{text}</pre>;
}

export function ExecutionOutput({ output, invocation }: { output: Output; invocation: DefinitionCall }) {
  const { t } = useTranslation();
  if (output.state === 'locked') return <Notice>{t('executionOutputLocked')}</Notice>;
  if (output.state === 'notShared') return <Notice>{t('executionOutputNotShared')}</Notice>;
  if (output.state === 'unrecorded') return <p className="text-muted-foreground">{t('executionNoRecordedOutput')}</p>;
  if (output.state === 'failed') return <ErrorNotice error={output.error} />;
  if (output.state === 'unavailable') return <Notice tone="warning">
    {t(output.error === 'identity_untrusted' ? 'executionOutputUntrusted' : output.error === 'forbidden' ? 'executionOutputForbidden' : 'executionOutputUnreadable')}
  </Notice>;
  const command = output.kind === 'command' ? CommandResult.safeParse(output.value) : null;
  if (command?.success) return <div className="flex min-w-0 flex-col gap-4">
    <Detail label={t('executionExitCode')}>{command.data.exitCode ?? '—'}</Detail>
    {command.data.signal && <Detail label={t('executionSignal')}>{command.data.signal}</Detail>}
    {command.data.stdout ? <div className="flex min-w-0 flex-col gap-2"><h3 className="text-sm font-medium">{t('executionOutput')}</h3><OutputText text={command.data.stdout} /></div> :
      <p className="text-muted-foreground">{t('executionNoTextOutput')}</p>}
    {command.data.stderr && <div className="flex min-w-0 flex-col gap-2"><h3 className="text-sm font-medium">{t('executionStderr')}</h3><OutputText text={command.data.stderr} /></div>}
    {command.data.timedOut && <Notice tone="warning">{t('executionTimedOut')}</Notice>}
    {command.data.truncated && <Notice tone="warning">{t('executionOutputTruncated')}</Notice>}
  </div>;
  const http = output.kind === 'http' ? HttpResult.safeParse(output.value) : null;
  if (http?.success) return <div className="flex min-w-0 flex-col gap-4">
    <Detail label={t('executionHttpStatus')}>{http.data.status}</Detail>
    {http.data.body ? <OutputText text={http.data.body} /> : <p className="text-muted-foreground">{t('executionNoTextOutput')}</p>}
  </div>;
  return <ExecutionResult invocation={invocation} value={output.value} />;
}

export function ExecutionResult({ invocation, value }: { invocation: DefinitionCall; value: JsonValue }) {
  const { t } = useTranslation();
  const resource = Resource.safeParse(value);
  if (resource.success) return <Button asChild variant="outline"><Link to={resourcePath(resource.data)}>{resource.data.name}</Link></Button>;
  const principal = Principal.safeParse(value);
  if (principal.success) return <Button asChild variant="outline"><Link to={'/p/' + principal.data.id}>{principal.data.name}</Link></Button>;
  if (value && typeof value === 'object' && !Array.isArray(value) && value.kind === 'connected' &&
    typeof value.id === 'string' && typeof invocation.input.ownerId === 'string')
    return <Button asChild variant="outline"><Link to={resourcePath({ ownerId: invocation.input.ownerId, kind: 'connection', id: value.id })}>{t('executionOpenConnection')}</Link></Button>;
  if (typeof value === 'string') return value ? <OutputText text={value} /> : <p className="text-muted-foreground">{t('executionNoTextOutput')}</p>;
  return <JsonView value={value} />;
}
