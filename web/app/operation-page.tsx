import { useEffect } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation, useRevalidator, useRouteLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { clientLoader as rootLoader } from './root';
import { ApprovalRequest, Resource } from '../../shared/contracts';
import type { ApprovalView, JsonValue } from '../../shared/contracts';
import { executionRequestState, OperationExecution } from '../../shared/operations';
import type { OperationInvocation } from '../../shared/operations';
import { atPointer } from '../../shared/values';
import { actionResult, api, ApiFailure, errorCode, formText, session } from './api';
import { connectionClient, operationClient } from './custody';
import { loadOperationForm, OperationInputFields, operationSubmission } from './operation-form';
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
function inputOperation(item: ApprovalView, actorId: string) {
  if (item.waiting) return { index: item.waiting.index, invocation: item.waiting.invocation };
  if (item.state !== 'pending') return null;
  const index = item.operations.findIndex((operation, index) => {
    const result = item.results[index];
    return operation.execution === 'keyholder' && (!result || (typeof result === 'object' && !Array.isArray(result) && ('error' in result || 'pending' in result)));
  });
  if (index < 0) return null;
  const { name, input } = item.operations[index]!;
  const invocation = { name, input };
  return { index, invocation: { name: invocation.name, input: substitute(invocation.input, actorId, item.from.id) } as OperationInvocation };
}
function configuration(invocation: OperationInvocation, input: OperationInvocation['input'], fields: string[]) {
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '')).map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
function OperationResult({ invocation, value }: { invocation: OperationInvocation; value: JsonValue }) {
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
  if (requestMode) return api('/requests/' + id, { signal }, ApprovalRequest);
  const execution = await api('/operation-executions/' + id, { signal }, OperationExecution);
  return ApprovalRequest.parse({ id, from: execution.creator, to: execution.responder, message: execution.message, proposal: execution.proposal,
    operations: execution.operations, state: executionRequestState(execution), results: execution.results, createdAt: execution.createdAt, expiresAt: execution.expiresAt,
    url: execution.url, returnUrl: null, refreshUrl: null, canRespond: execution.canRespond, canCancel: execution.canCancel, executionState: execution.state, waiting: execution.waiting });
}
export async function clientLoader({ params, request }: PageArgs) {
  const requestMode = new URL(request.url).pathname.startsWith('/requests/');
  const fragment = new URLSearchParams(window.location.hash.slice(1)), token = fragment.get('token');
  if (token) {
    await api(`/requests/${params.id}/redeem`, { method: 'POST', body: { token } });
    history.replaceState(null, '', window.location.pathname);
  }
  const account = await session(request);
  let item: ApprovalView;
  try { item = await readItem(params.id!, requestMode, request.signal); }
  catch (error) {
    if (!account.principal && error instanceof ApiFailure && [401, 403].includes(error.status))
      throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
    throw error;
  }
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError: string | null = null;
  if (item.canRespond && !account.requestId && item.waiting?.continuation) {
    const continuationId = item.waiting.continuation.id;
    try {
      if (item.waiting.continuation.kind === 'connection') progress = await (await connectionClient()).progress(item.waiting.continuation.id);
      else await (await operationClient()).continue(item.id);
    } catch (error) { operationError = errorCode(error); }
    item = await readItem(params.id!, requestMode);
    if (item.waiting?.continuation?.id !== continuationId) { progress = null; operationError = null; }
  }
  const failed = item.results.find(result => result && typeof result === 'object' && !Array.isArray(result) && 'error' in result);
  if (failed && typeof failed === 'object' && !Array.isArray(failed) && failed.error && typeof failed.error === 'object' && !Array.isArray(failed.error))
    operationError ??= typeof failed.error.code === 'string' ? failed.error.code : 'failure';
  const current = inputOperation(item, account.principal?.id ?? '');
  const inputForm = current && item.canRespond && !account.requestId && !item.waiting?.continuation
    ? await loadOperationForm(current.invocation) : null;
  if (['pending', 'running'].includes(item.state) && item.from.id === account.principal?.id)
    item.code = sessionStorage.getItem('foundation.request.' + item.id) ?? undefined;
  else sessionStorage.removeItem('foundation.request.' + item.id);
  return { item, account, current, inputForm, progress, operationError, requestMode };
}
export async function clientAction({ params, request }: PageArgs) {
  return actionResult(async () => {
    const requestMode = new URL(request.url).pathname.startsWith('/requests/'), path = (requestMode ? '/requests/' : '/operation-executions/') + params.id;
    const form = await request.formData(), intent = formText(form, 'intent');
    let item = await readItem(params.id!, requestMode);
    if (intent === 'cancel' || intent === 'decline') {
      if (intent === 'decline' && item.waiting?.continuation?.kind === 'connection')
        await (await connectionClient()).cancel(item.waiting.continuation.id);
      await api(path + '/' + intent, { method: 'POST', body: {} });
      return readItem(params.id!, requestMode);
    }
    if (intent === 'acceptConnection') {
      if (item.waiting?.continuation?.kind !== 'connection') throw new Error('Continue the pending connection.');
      await (await connectionClient()).accept(item.waiting.continuation.id);
      return readItem(params.id!, requestMode);
    }
    const account = await session(), current = inputOperation(item, account.principal!.id);
    const data = current ? await loadOperationForm(current.invocation) : null;
    const prepared = data ? operationSubmission(data, form) : null;
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
    } else if (prepared && current) await (await operationClient()).configure(item.id, configuration(current.invocation, prepared.input, item.operations[current.index]!.configure));
    if (item.waiting && prepared) await (await operationClient()).continue(item.id, prepared.material);
    return readItem(params.id!, requestMode);
  });
}
export default function OperationPage() {
  const { t, i18n } = useTranslation(), { item, account, current, inputForm, progress, operationError, requestMode } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const pending = ['pending', 'running'].includes(item.state), requester = item.from.id === account.principal?.id;
  const root = useRouteLoaderData<typeof rootLoader>('root'), revalidator = useRevalidator();
  const needsKeys = !!current && !!account.requestId;
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle') void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(pending, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  return <Page title={requestMode ? t('requests') : item.operations.length === 1 ? (i18n.language === 'ja' ? item.operations[0]!.title.ja : item.operations[0]!.title.en) : t('operation')} narrow>
    <ErrorNotice error={result && 'error' in result ? result.error : operationError} />
    <Panel>
      <Detail label={t('status')}><State value={requestMode ? item.state : item.executionState} /></Detail>
      <Detail label={t(requestMode ? 'requestedBy' : 'operationInitiator')}>{item.from.name}<Copy value={item.from.id} /></Detail>
      {(item.to || requestMode) && <Detail label={t(requestMode ? 'requestedTo' : 'operationResponder')}>{item.to?.name ?? '—'}</Detail>}
      <Detail label={t('expires')}><DateText value={item.expiresAt} /></Detail>
      {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
        (item.message || requestMode) && <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
      {item.code && <Detail label={t('code')}>{item.code}<Copy value={item.code} /></Detail>}
      {requester && <Detail label={t('url')}><Link className="underline underline-offset-4" to={new URL(item.url).pathname}>{item.url}</Link><Copy value={item.url} /></Detail>}
    </Panel>
    <Form method="post">
      <div className="flex min-w-0 flex-col gap-6">
        {!item.proposal && item.operations.map((operation, index) => {
          const privateOperation = operation.execution === 'keyholder';
          return <Panel key={index} title={`${index + 1}. ${i18n.language === 'ja' ? operation.title.ja : operation.title.en}`}>
            {current?.index === index && inputForm && <OperationInputFields data={inputForm} />}
            {item.waiting?.index === index && progress && <ConnectionProgress progress={progress} acceptIntent="acceptConnection" cancelIntent={requester ? 'cancel' : 'decline'} />}
            {!privateOperation && <JsonView value={operation.input} />}
            {!privateOperation && operation.inputs.filter(input => !input.secret).map((input, inputIndex) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
              {input.multiline ? <TextareaField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                disabled={!item.canRespond || !pending} required={item.canRespond && pending} rows={3} /> :
                <InputField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                  disabled={!item.canRespond || !pending} required={item.canRespond && pending} />}
              {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
            </div>)}
          </Panel>;
        })}
        {item.state === 'pending' && item.canRespond && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
        {needsKeys && <Notice tone="info" action={<Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/operations/') + item.id)}>{t('signin')}</Link></Button>}>
          {t('signinForPrivateInput')}
        </Notice>}
        {pending && item.canRespond && !needsKeys && !item.waiting?.continuation && (item.state === 'pending' || current) && <div className="flex flex-wrap items-center gap-4">
          <Button type="submit" name="intent" value={item.state === 'pending' ? 'approve' : 'continue'} disabled={navigation.state !== 'idle'}>
            {t(item.state === 'pending' && requestMode ? 'approve' : current?.invocation.name === 'connection.connect' ? 'connect' : current?.invocation.name === 'connection.revoke' ? 'revokeConnection' : current?.invocation.name === 'run.execute' ? 'execute' : item.state === 'pending' ? 'approve' : 'save')}
          </Button>
          {(requestMode || !requester) && <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('decline')}</Button>}
        </div>}
        {pending && requester && item.canCancel && !progress && <Button type="submit" name="intent" value="cancel" formNoValidate variant="destructive">{t(requestMode ? 'cancelRequest' : 'cancelOperation')}</Button>}
        {item.state === 'running' && item.canRespond && !current && (requestMode || !requester) && <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('decline')}</Button>}
      </div>
    </Form>
    {!pending && item.results.some(result => result !== null) && <Panel title={t('result')}>
      <div className="flex flex-col items-start gap-4">{item.results.map((value, index) => value !== null &&
        <OperationResult key={index} invocation={item.operations[index]!} value={value} />)}</div>
    </Panel>}
    {!account.principal && pending && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/operations/') + item.id)}>{t('signinToApprove')}</Link></Button>}
    {!pending && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('retry')}</a></Button>}
  </Page>;
}
