import { useEffect } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation, useRevalidator, useRouteLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { clientLoader as rootLoader } from './root';
import { ApprovalRequest, Resource } from '../../shared/contracts';
import type { ApprovalView, JsonValue } from '../../shared/contracts';
import { Execution } from '../../shared/executions';
import type { DefinitionCall, ExecutionView } from '../../shared/executions';
import { Task } from '../../shared/runtime-protocol';
import { atPointer } from '../../shared/values';
import { actionResult, api, ApiFailure, errorCode, formText, session } from './api';
import { connectionClient, custodyClient, executionClient } from './custody';
import { loadExecutionForm, ExecutionInputFields, executionSubmission } from './execution-form';
import { ConnectionProgress } from './connection-progress';
import { resourcePath } from './navigation';
import { Button } from './components/ui/button';
import { InputField, TextareaField } from './form-fields';
import { Copy, DateText, Detail, ErrorNotice, ExternalLink, JsonView, Notice, Page, Panel, ProposalText, State, usePolling } from './components';

function substitute(value: JsonValue, approver: string, requester: string): JsonValue {
  if (value === '$approver') return approver;
  if (value === '$requester') return requester;
  if (Array.isArray(value)) return value.map(item => substitute(item, approver, requester));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, substitute(child, approver, requester)]));
  return value;
}
type PageExecution = ExecutionView & {
  from: ExecutionView['creator']; to: ApprovalView['to']; message: string; proposal: import('zod').z.infer<typeof import('../../shared/contracts').Proposal> | null;
  canRespond: boolean;
  delivery: ApprovalView | null; returnUrl: string | null; refreshUrl: string | null;
};
function inputOperation(item: PageExecution, actorId: string) {
  if (!['waiting', 'running'].includes(item.state)) return null;
  if (item.waiting) return { index: item.waiting.index, invocation: item.waiting.invocation };
  if (item.wait !== 'approval') return null;
  const index = item.operations.findIndex((operation, index) => {
    const result = item.results[index];
    return operation.execution === 'keyholder' && (!result || (typeof result === 'object' && !Array.isArray(result) && ('error' in result || 'pending' in result)));
  });
  if (index < 0) return null;
  const { name, input } = item.operations[index]!;
  const invocation = { name, input };
  return { index, invocation: { name: invocation.name, input: substitute(invocation.input, actorId, item.from.id) } as DefinitionCall };
}
function configuration(invocation: DefinitionCall, input: DefinitionCall['input'], fields: string[]) {
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '')).map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
function ExecutionResultView({ invocation, value }: { invocation: DefinitionCall; value: JsonValue }) {
  const { t } = useTranslation();
  const resource = Resource.safeParse(value);
  if (resource.success) return <Button asChild variant="outline"><Link to={resourcePath(resource.data)}>{resource.data.name}</Link></Button>;
  if (value && typeof value === 'object' && !Array.isArray(value) && value.kind === 'connected' &&
    typeof value.id === 'string' && typeof invocation.input.ownerId === 'string')
    return <Button asChild variant="outline"><Link to={resourcePath({ ownerId: invocation.input.ownerId, kind: 'connection', id: value.id })}>{t('details')}</Link></Button>;
  return <JsonView value={value} />;
}
type PageArgs = { params: { id?: string }; request: Request };
async function readItem(id: string, requestMode: boolean, signal?: AbortSignal) {
  let delivery = requestMode ? await api('/requests/' + id, { signal }, ApprovalRequest) : null;
  const execution = await api('/executions/' + (delivery?.executionId ?? id), { signal }, Execution);
  if (!delivery && execution.approval?.requestId) delivery = await api('/requests/' + execution.approval.requestId, { signal }, ApprovalRequest);
  return { ...execution, from: delivery?.from ?? execution.creator, to: delivery?.to ?? null,
    message: delivery?.message ?? '', proposal: execution.approval?.proposal ?? null, canRespond: execution.canContinue,
    url: requestMode ? delivery!.url : execution.url,
    delivery,
    returnUrl: delivery?.returnUrl ?? null, refreshUrl: delivery?.refreshUrl ?? null } satisfies PageExecution;
}
export async function clientLoader({ params, request }: PageArgs) {
  const requestMode = new URL(request.url).pathname.startsWith('/requests/');
  const fragment = new URLSearchParams(window.location.hash.slice(1)), token = fragment.get('token');
  if (token) {
    await api(`/requests/${params.id}/redeem`, { method: 'POST', body: { token } });
    history.replaceState(null, '', window.location.pathname);
  }
  const account = await session(request);
  let item: PageExecution;
  try { item = await readItem(params.id!, requestMode, request.signal); }
  catch (error) {
    if (!account.principal && error instanceof ApiFailure && [401, 403].includes(error.status))
      throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
    throw error;
  }
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError: string | null = null;
  operationError = item.error?.code ?? null;
  if (item.canRespond && !account.requestId && item.waiting?.continuation) {
    const continuationId = item.waiting.continuation.id;
    try {
      if (item.waiting.continuation.kind === 'connection') progress = await (await connectionClient()).progress(item.waiting.continuation.id);
      else await (await executionClient()).continue(item.id);
    } catch (error) { operationError = errorCode(error); }
    item = await readItem(params.id!, requestMode);
    if (item.waiting?.continuation?.id !== continuationId) { progress = null; operationError = null; }
  }
  const failed = item.results.find(result => result && typeof result === 'object' && !Array.isArray(result) && 'error' in result);
  if (failed && typeof failed === 'object' && !Array.isArray(failed) && failed.error && typeof failed.error === 'object' && !Array.isArray(failed.error))
    operationError ??= typeof failed.error.code === 'string' ? failed.error.code : 'failure';
  const current = inputOperation(item, account.principal?.id ?? '');
  const inputForm = current && item.canRespond && !account.requestId && !item.waiting?.continuation
    ? await loadExecutionForm(current.invocation) : null;
  if (['waiting', 'running'].includes(item.state) && item.from.id === account.principal?.id)
    item.code = sessionStorage.getItem('foundation.request.' + (item.delivery?.id ?? item.id)) ?? undefined;
  else sessionStorage.removeItem('foundation.request.' + (item.delivery?.id ?? item.id));
  const outputs: Record<number, JsonValue> = {};
  if (!account.requestId && account.principal) for (const step of item.steps) {
    const run = step.runs.filter(run => run.kind === 'run').at(-1);
    if (!run || !['succeeded', 'failed', 'uncertain', 'cancelled'].includes(step.state)) continue;
    try {
      const task = await api('/runtime/runs/' + run.id, {}, Task);
      if (task.receipt) {
        const result = await (await custodyClient()).result(task);
        if (result?.ok) outputs[step.index] = result.result;
        else if (result?.error) operationError ??= result.error.code;
      }
    } catch (error) { operationError ??= errorCode(error); }
  }
  return { item, account, current, inputForm, progress, operationError, requestMode, outputs };
}
export async function clientAction({ params, request }: PageArgs) {
  return actionResult(async () => {
    const requestMode = new URL(request.url).pathname.startsWith('/requests/'), path = (requestMode ? '/requests/' : '/executions/') + params.id;
    const form = await request.formData(), intent = formText(form, 'intent');
    let item = await readItem(params.id!, requestMode);
    if (intent === 'cancel' || intent === 'decline') {
      const cancellationPath = item.delivery?.state === 'pending' && (requestMode || intent === 'decline')
        ? '/requests/' + item.delivery.id : '/executions/' + item.id;
      await api(cancellationPath + '/' + intent, { method: 'POST', body: {} });
      return readItem(params.id!, requestMode);
    }
    if (intent === 'resume') {
      await api('/executions/' + item.id + '/resume', { method: 'POST', body: {} }, Execution);
      return readItem(params.id!, requestMode);
    }
    if (intent === 'acceptConnection') {
      if (item.waiting?.continuation?.kind !== 'connection') throw new Error('Continue the pending connection.');
      await (await connectionClient()).accept(item.waiting.continuation.id);
      return readItem(params.id!, requestMode);
    }
    const account = await session(), current = inputOperation(item, account.principal!.id);
    const data = current ? await loadExecutionForm(current.invocation) : null;
    const prepared = data ? executionSubmission(data, form) : null;
    if (intent === 'approve') {
      const values = item.operations.map((operation, index) => Object.fromEntries(operation.inputs.filter(input => !input.secret).map((input, inputIndex) => {
        const key = `input.${index}.${inputIndex}`;
        return [input.pointer, String(form.has(key) ? form.get(key) : index === current?.index && prepared
          ? atPointer(prepared.input, input.pointer) ?? '' : '')];
      })));
      const choices = item.operations.map((_operation, index) => index === current?.index && prepared
        ? configuration(current.invocation, prepared.input, item.operations[current.index]!.configure) : {});
      await api(path + (requestMode ? '/approve' : '/respond'), { method: 'POST',
        body: { values, configuration: choices, code: formText(form, 'code') || undefined } });
      item = await readItem(params.id!, requestMode);
    } else if (prepared && current) await (await executionClient()).configure(item.id, configuration(current.invocation, prepared.input, item.operations[current.index]!.configure));
    if (item.waiting && prepared) await (await executionClient()).continue(item.id, prepared.material);
    return readItem(params.id!, requestMode);
  });
}
export default function ExecutionPage() {
  const { t, i18n } = useTranslation(), { item, account, current, inputForm, progress, operationError, requestMode, outputs } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const pending = ['waiting', 'running'].includes(item.state), requester = item.from.id === account.principal?.id;
  const awaitingApproval = item.wait === 'approval', canDecline = item.delivery?.state === 'pending' && item.delivery.canRespond;
  const root = useRouteLoaderData<typeof rootLoader>('root'), revalidator = useRevalidator();
  const needsKeys = !!current && !!account.requestId;
  const completedResults = item.results.flatMap((value, index) => value !== null &&
    (item.steps[index]?.state === 'succeeded' || outputs[index] !== undefined) ? [{ index, value: outputs[index] ?? value }] : []);
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle') void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(pending, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  return <Page title={requestMode ? t('requests') : item.operations.length === 1 ? (i18n.language === 'ja' ? item.operations[0]!.title.ja : item.operations[0]!.title.en) : t('execution')} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    <Panel>
      <Detail label={t('status')}><State value={requestMode ? item.delivery!.state : item.state} /></Detail>
      <Detail label={t(requestMode ? 'requestedBy' : 'operationInitiator')}>{item.from.name}<Copy value={item.from.id} /></Detail>
      {(item.to || requestMode) && <Detail label={t(requestMode ? 'requestedTo' : 'operationResponder')}>{item.to?.name ?? '—'}</Detail>}
      <Detail label={t('expires')}><DateText value={item.expiresAt} /></Detail>
      {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
        (item.message || requestMode) && <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
      {item.code && <Detail label={t('code')}>{item.code}<Copy value={item.code} /></Detail>}
      {requester && <Detail label={t('url')}><Link className="underline underline-offset-4" to={new URL(item.url).pathname}>{item.url}</Link><Copy value={item.url} /></Detail>}
      {item.delivery && <Detail label={t(requestMode ? 'execution' : 'requests')}><Link className="underline underline-offset-4" to={(requestMode ? '/executions/' + item.id : '/requests/' + item.delivery.id)}>{t('details')}</Link></Detail>}
    </Panel>
    <Form method="post">
      <div className="flex min-w-0 flex-col gap-6">
        {!item.proposal && item.operations.map((operation, index) => {
          const privateOperation = operation.execution === 'keyholder';
          return <Panel key={index} title={`${index + 1}. ${i18n.language === 'ja' ? operation.title.ja : operation.title.en}`}>
            {current?.index === index && inputForm && <ExecutionInputFields data={inputForm} />}
            {item.waiting?.index === index && progress && <ConnectionProgress progress={progress} acceptIntent="acceptConnection" cancelIntent="cancel" />}
            {!privateOperation && awaitingApproval && <JsonView value={operation.input} />}
            <Detail label={t('status')}><State value={item.steps[index]?.state ?? item.state} /></Detail>
            {!privateOperation && operation.inputs.filter(input => !input.secret).map((input, inputIndex) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
              {input.multiline ? <TextareaField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                disabled={!item.canRespond || !pending} required={item.canRespond && pending} rows={3} /> :
                <InputField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                  disabled={!item.canRespond || !pending} required={item.canRespond && pending} />}
              {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
            </div>)}
          </Panel>;
        })}
        {awaitingApproval && item.canRespond && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
        {needsKeys && <Notice tone="info" action={<Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/executions/') + (item.delivery?.id ?? item.id))}>{t('signin')}</Link></Button>}>
          {t('signinForPrivateInput')}
        </Notice>}
        {pending && item.canRespond && !needsKeys && !item.waiting?.continuation && (awaitingApproval || current) && <div className="flex flex-wrap items-center gap-4">
          <Button type="submit" name="intent" value={awaitingApproval ? 'approve' : 'continue'} disabled={navigation.state !== 'idle'}>
            {t(awaitingApproval && requestMode ? 'approve' : current?.invocation.name === 'connection.connect' ? 'connect' : current?.invocation.name === 'connection.revoke' ? 'revokeConnection' : current?.invocation.name === 'run.execute' ? 'execute' : awaitingApproval ? 'approve' : 'save')}
          </Button>
          {canDecline && <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('decline')}</Button>}
        </div>}
        {pending && item.canCancel && !progress && !canDecline && <Button type="submit" name="intent" value="cancel" formNoValidate variant="destructive">{t(requestMode && item.delivery?.state === 'pending' ? 'cancelRequest' : 'cancelOperation')}</Button>}
        {item.state === 'failed' && item.canRespond && !needsKeys && <Button type="submit" name="intent" value="resume">{t('retry')}</Button>}
      </div>
    </Form>
    {completedResults.length > 0 && <Panel title={t('result')}>
      <div className="flex flex-col items-start gap-4">{completedResults.map(({ value, index }) =>
        <ExecutionResultView key={index} invocation={item.operations[index]!} value={value} />)}</div>
    </Panel>}
    {!account.principal && pending && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/executions/') + (item.delivery?.id ?? item.id))}>{t('signinToApprove')}</Link></Button>}
    {!pending && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('retry')}</a></Button>}
  </Page>;
}
