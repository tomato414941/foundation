import { useEffect } from 'react';
import { Form, Link, redirect, redirectDocument, useActionData, useLoaderData, useLocation, useNavigation, useRevalidator, useRouteLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ArrowUpRight } from 'lucide-react';
import type { clientLoader as rootLoader } from './root';
import { ApprovalRequest } from '../../shared/contracts';
import type { ApprovalView, JsonValue } from '../../shared/contracts';
import { Execution } from '../../shared/executions';
import type { DefinitionCall, ExecutionView } from '../../shared/executions';
import { atPointer } from '../../shared/values';
import { actionResult, api, ApiFailure, errorCode, formText, holdingKeys, session } from './api';
import { connectionClient, custodyClient, executionClient } from './custody';
import { getIdentity, requireKeys, resealNow, useResealing } from './keys';
import { ResealingNotice } from './resealing-notice';
import { RecipientAccessNotice } from './recipient-verification';
import { loadExecutionForm, ExecutionInputFields, executionSubmission } from './execution-form';
import { ConnectionProgress } from './connection-progress';
import { ConnectionUsers } from './connection-users';
import { ConnectionRequestReview, connectionRequestAction } from './connection-request-review';
import { loadRequestConnection, requestConnectionMethod } from './request-connection';
import { DelegationReview, loadDelegationReviews } from './delegation-review';
import { ExecutionFacts, ExecutionOutput, ExecutionResult, executionTitle, loadExecutionDetails } from './execution-details';
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
    (invocation.input[key] == null || invocation.input[key] === '' ||
      typeof input[key] === 'object' && !Array.isArray(input[key]) && JSON.stringify(invocation.input[key]) !== JSON.stringify(input[key])))
    .map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
// Lines that change who opens what a principal holds: once approved, this browser seals those items again.
const resealing = (item: PageExecution) => !item.proposal && item.operations.some(operation =>
  ['relation.draw', 'relation.erase'].includes(operation.name) && ['delegate', 'member'].includes(String(operation.input.relation)));
// The principal a line awaiting approval lets open what the approver holds, as its delegate or member.
function lineSubject(item: PageExecution, approverId: string) {
  const operation = item.proposal ? undefined : item.operations.find(operation => operation.name === 'relation.draw' &&
    ['delegate', 'member'].includes(String(operation.input.relation)));
  const subject = operation ? substitute(operation.input.subjectId ?? null, approverId, item.from.id) : null;
  return typeof subject === 'string' && subject !== approverId ? subject : null;
}
// Approving such a line has this browser seal for the subject at once, so the subject's public key is verified before,
// or by the fingerprint in the link the subject gave. While it is not, this names the subject. It reads what the
// approver verified, which needs the approver's private key in this browser.
async function unverifiedSubject(item: PageExecution, approverId: string, id: string) {
  const subject = lineSubject(item, approverId);
  if (!subject) return null;
  if (subject === item.from.id && sessionStorage.getItem('foundation.fingerprint.request.' + id)) return null;
  try { if (await (await custodyClient()).verifiedIdentity(subject)) return null; }
  catch (error) { if (error instanceof ApiFailure && error.code === 'key_binding_required') return null; throw error; }
  return subject === item.from.id ? item.from.name
    : await api<{ name: string }>('/identities/' + subject).then(identity => identity.name, () => subject);
}
type PageArgs = { params: { id?: string }; request: Request };
async function readItem(id: string, requestMode: boolean, signal?: AbortSignal) {
  let delivery = requestMode ? await api('/requests/' + id, { signal }, ApprovalRequest) : null;
  const execution = await api('/executions/' + (delivery?.executionId ?? id), { signal }, Execution);
  if (!delivery && execution.requests.length) {
    try { delivery = await api('/requests/' + execution.requests.at(-1), { signal }, ApprovalRequest); }
    catch (error) { if (!(error instanceof ApiFailure && error.status === 403)) throw error; }
  }
  return { ...execution, from: delivery?.from ?? execution.creator, to: delivery?.to ?? null,
    message: delivery?.message ?? '', proposal: execution.approval?.proposal ?? null, canRespond: execution.canContinue,
    url: requestMode ? delivery!.url : execution.url,
    delivery,
    returnUrl: delivery?.returnUrl ?? null, refreshUrl: delivery?.refreshUrl ?? null } satisfies PageExecution;
}
export async function clientLoader({ params, request }: PageArgs) {
  const requestMode = new URL(request.url).pathname.startsWith('/requests/');
  const fragment = new URLSearchParams(window.location.hash.slice(1)), token = fragment.get('token');
  // The requester's public key fingerprint comes in the link's fragment, which never reaches the server. It is kept for
  // this tab until the request is approved, so that signing in on the way keeps it.
  const linked = fragment.get('fingerprint');
  if (linked) sessionStorage.setItem('foundation.fingerprint.request.' + params.id, linked);
  if (token) {
    await api(`/requests/${params.id}/redeem`, { method: 'POST', body: { token } });
    history.replaceState(null, '', window.location.pathname);
  }
  const account = await session(request);
  if (account.principal && !account.requestId) await holdingKeys(request, account.principal);
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
  const operation = item.operations.length === 1 ? item.operations[0] : null;
  const [inputForm, requestConnection, delegationReviews] = await Promise.all([
    current && item.canRespond && !account.requestId && !item.waiting?.continuation ? loadExecutionForm(current.invocation) : null,
    requestMode && operation?.name === 'connection.connect' && item.from.id !== account.principal?.id ? loadRequestConnection({ name: operation.name,
      input: substitute(operation.input, account.principal?.id ?? '', item.from.id) as DefinitionCall['input'] }, request.signal, !account.requestId) : null,
    item.wait === 'approval' && !item.proposal ? loadDelegationReviews(item.operations, {
      approver: item.canRespond ? account.principal : null, requester: item.creator,
      principals: [...account.principals, item.from, ...(item.to ? [item.to] : [])],
      inspect: !!account.principal && !account.requestId, signal: request.signal,
    }) : [],
  ]);
  if (['waiting', 'running'].includes(item.state) && item.from.id === account.principal?.id)
    item.code = sessionStorage.getItem('foundation.request.' + (item.delivery?.id ?? item.id)) ?? undefined;
  else sessionStorage.removeItem('foundation.request.' + (item.delivery?.id ?? item.id));
  const details = requestConnection && item.from.id !== account.principal?.id
    ? { steps: [], environments: [], initiator: item.creator }
    : await loadExecutionDetails(item, !!account.principal && !account.requestId, request.signal);
  const unverified = account.principal && !account.requestId && item.canRespond && item.wait === 'approval' &&
    ['waiting', 'running'].includes(item.state) && await getIdentity(account.principal.id)
    ? await unverifiedSubject(item, account.principal.id, params.id!) : null;
  return { item, account, current, inputForm, progress, operationError, requestMode, requestConnection, delegationReviews, details, unverified };
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
    const account = await session(), approverId = account.principal!.id, current = inputOperation(item, approverId);
    // Approving with the fingerprint the requester linked first verifies its public key, for each of the approver's devices.
    const linked = intent === 'approve' ? new URLSearchParams(window.location.hash.slice(1)).get('fingerprint')
      ?? sessionStorage.getItem('foundation.fingerprint.request.' + params.id) : null;
    // Entering input, verifying a public key, and sealing items again for a changed line all use the private key, so a
    // passkey opens it first when this browser does not hold it, before anything is answered.
    if (current || linked || intent === 'approve' && resealing(item)) await requireKeys(approverId);
    const data = current ? await loadExecutionForm(current.invocation) : null;
    const prepared = data ? executionSubmission(data, form) : null;
    if (intent === 'approve') {
      if (!linked && !account.requestId && await unverifiedSubject(item, approverId, params.id!))
        throw new ApiFailure('identity_untrusted');
      if (linked) await (await custodyClient()).trustIdentity(item.from.id, linked);
      const values = item.operations.map((operation, index) => Object.fromEntries(operation.inputs.filter(input => !input.secret).map((input, inputIndex) => {
        const key = `input.${index}.${inputIndex}`;
        return [input.pointer, String(form.has(key) ? form.get(key) : index === current?.index && prepared
          ? atPointer(prepared.input, input.pointer) ?? '' : '')];
      })));
      const choices = item.operations.map((_operation, index) => index === current?.index && prepared
        ? configuration(current.invocation, prepared.input, item.operations[current.index]!.configure) : {});
      await api(path + (requestMode ? '/approve' : '/respond'), { method: 'POST',
        body: { values, configuration: choices, code: formText(form, 'code') || undefined } });
      sessionStorage.removeItem('foundation.fingerprint.request.' + params.id);
      if (resealing(item)) await resealNow(approverId, params.id!);
      item = await readItem(params.id!, requestMode);
    } else if (prepared && current) await (await executionClient()).configure(item.id, configuration(current.invocation, prepared.input, item.operations[current.index]!.configure));
    if (item.waiting && prepared) {
      const progress = await (await executionClient()).continue(item.id, prepared.material);
      if (requestMode && current?.invocation.name === 'connection.connect' && 'kind' in progress && progress.kind === 'authorize') {
        const method = await requestConnectionMethod(String(current.invocation.input.methodId));
        if (method.kind !== 'approval' && ['http:', 'https:'].includes(new URL(progress.url).protocol))
          return redirectDocument(progress.url);
      }
    }
    return readItem(params.id!, requestMode);
  });
}
export default function ExecutionPage() {
  const { t, i18n } = useTranslation(), { item, account, current, inputForm, progress, operationError, requestMode, requestConnection, delegationReviews, details, unverified } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const pending = ['waiting', 'running'].includes(item.state), requester = item.from.id === account.principal?.id;
  const pageId = requestMode ? item.delivery?.id ?? item.id : item.id;
  const location = useLocation();
  const fingerprint = new URLSearchParams(location.hash.slice(1)).get('fingerprint')
    ?? sessionStorage.getItem('foundation.fingerprint.request.' + pageId);
  const shareUrl = item.url + (fingerprint ? '#fingerprint=' + encodeURIComponent(fingerprint) : '');
  const sealing = useResealing(account.principal?.id);
  const approvalAccepted = pending && navigation.state !== 'idle' && sealing?.requestId === pageId;
  const awaitingApproval = item.wait === 'approval', canDecline = item.delivery?.state === 'pending' && item.delivery.canRespond;
  const root = useRouteLoaderData<typeof rootLoader>('root'), revalidator = useRevalidator();
  const needsKeys = !!current && !!account.requestId;
  const recipientRequest = requestMode && !requester;
  const focusedConnection = !!requestConnection && !requester;
  const service = requestConnection?.method?.defaultName ?? requestConnection?.name ?? '';
  const connectionAction = requestConnection?.reconnecting ? 'reconnect' : 'connect';
  const connectionCancelled = item.delivery?.state === 'declined' || item.state === 'cancelled' && item.delivery?.state !== 'expired';
  const connectionTitle = requestConnection?.reconnecting
    ? item.state === 'succeeded' ? 'requestReconnected' : connectionCancelled ? 'requestReconnectCancelled' : 'requestReconnect'
    : item.state === 'succeeded' ? 'requestConnected' : connectionCancelled ? 'requestConnectCancelled' : 'requestConnect';
  const title = focusedConnection && service ? t(connectionTitle, { name: service })
    : focusedConnection ? t(connectionAction)
    : recipientRequest && !item.proposal && item.operations.length === 1 ? executionTitle(item.operations[0]!, i18n.language)
    : t(requestMode ? 'requests' : 'executionDetail');
  const showSteps = pending || !recipientRequest && item.operations.length > 1;
  const completedResults = item.steps.filter(step => {
    const value = item.results[step.index];
    if (step.state !== 'succeeded' && value && typeof value === 'object' && !Array.isArray(value) && value.pending === true)
      return false;
    if (recipientRequest && value && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === 1 && value.ok === true && !details.steps[step.index]?.output) return false;
    return details.steps[step.index]?.output || step.state === 'succeeded' && value !== null && value !== undefined;
  });
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle') void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(pending, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  const form = !approvalAccepted && (showSteps || item.state === 'failed' && item.canRespond) && <Form method="post">
    <div className="flex min-w-0 flex-col gap-6">
      {!item.proposal && (pending || item.operations.length > 1) && item.operations.map((operation, index) => {
        const privateOperation = operation.execution === 'keyholder';
        const Container = recipientRequest ? 'div' : Panel;
        const heading = item.operations.length > 1 ? `${index + 1}. ${executionTitle(operation, i18n.language)}` : executionTitle(operation, i18n.language);
        return <Container key={index} title={recipientRequest ? undefined : heading}>
          <div className="flex min-w-0 flex-col gap-4">
            {recipientRequest && item.operations.length > 1 && <h2 className="text-sm font-semibold">{heading}</h2>}
            {current?.index === index && inputForm && <ExecutionInputFields data={inputForm}
              requestPrincipalId={recipientRequest && (focusedConnection || operation.name === 'connection.authorize') ? account.principal?.id : undefined} />}
            {item.waiting?.index === index && progress && !focusedConnection && <ConnectionProgress progress={progress} cancelIntent="cancel" />}
            {!privateOperation && awaitingApproval && (delegationReviews[index]
              ? <DelegationReview review={delegationReviews[index]} /> : <JsonView value={operation.input} />)}
            {(!recipientRequest || item.operations.length > 1) && <Detail label={t('status')}><State value={item.steps[index]?.state ?? item.state} /></Detail>}
            {item.operations.length > 1 && details.steps[index] && <ExecutionFacts details={details.steps[index]} environments={details.environments} />}
            {pending && !privateOperation && operation.inputs.filter(input => !input.secret).map((input, inputIndex) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
              {input.multiline ? <TextareaField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                disabled={!item.canRespond || !pending} required={item.canRespond && pending} rows={3} /> :
                <InputField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                  disabled={!item.canRespond || !pending} required={item.canRespond && pending} />}
              {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
            </div>)}
          </div>
        </Container>;
      })}
      {focusedConnection && pending && requestConnection?.usersConfigured && <ConnectionUsers users={requestConnection.users} review />}
      {focusedConnection && progress && <ConnectionProgress progress={progress} cancelIntent="cancel" review
        authorization={{ label: t('requestContinueAtService', { name: service }), newWindow: requestConnection?.method?.kind === 'approval' }} />}
      {awaitingApproval && item.canRespond && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
      {needsKeys && <Notice tone="info" action={<Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/executions/') + (item.delivery?.id ?? item.id))}>{t('signin')}</Link></Button>}>
        {t(recipientRequest ? 'requestSignInHelp' : 'signinForPrivateInput')}
      </Notice>}
      {unverified && <Notice tone="warning">{t('approvalUnverified', { name: unverified })}</Notice>}
      {pending && item.canRespond && !needsKeys && !item.waiting?.continuation && (awaitingApproval || current) && <div className="flex flex-wrap items-center gap-4">
        <Button className={focusedConnection ? connectionRequestAction : undefined} type="submit" name="intent" value={awaitingApproval ? 'approve' : 'continue'}
          loading={focusedConnection && navigation.state !== 'idle'} disabled={navigation.state !== 'idle' || (awaitingApproval && !!unverified)}>
          {focusedConnection ? requestConnection?.method?.registration.kind === 'authorization'
            ? t(requestConnection.reconnecting ? 'requestReconnectAtService' : 'requestConnectAtService', { name: service })
            : t(connectionAction)
            : t(awaitingApproval && requestMode ? 'approve' : current?.invocation.name === 'connection.connect' ? 'connect' : current?.invocation.name === 'connection.revoke' ? 'disconnect' : current?.invocation.name === 'run.execute' ? 'execute' : awaitingApproval ? 'approve' : 'save')}
          {focusedConnection && requestConnection?.method?.registration.kind === 'authorization' && <ArrowUpRight aria-hidden="true" />}
        </Button>
        {canDecline && <Button className={focusedConnection ? 'min-h-12 px-4 text-muted-foreground' : undefined} type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('cancel')}</Button>}
      </div>}
      {pending && item.canCancel && !progress && !canDecline && <Button type="submit" name="intent" value="cancel" formNoValidate variant="destructive">{t(requestMode && item.delivery?.state === 'pending' ? 'cancelRequest' : 'cancelOperation')}</Button>}
      {item.state === 'failed' && item.canRespond && !needsKeys && <Button type="submit" name="intent" value="resume">{t('retry')}</Button>}
    </div>
  </Form>;
  const output = !focusedConnection && completedResults.length > 0 && <div className="flex min-w-0 flex-col gap-6">{completedResults.map(({ index }) => {
    const value = item.results[index], output = details.steps[index]?.output;
    const runtimeResult = value && typeof value === 'object' && !Array.isArray(value) && value.kind === 'run';
    return <div key={index} className="flex min-w-0 flex-col gap-4">
      {item.operations.length > 1 && <h3 className="text-sm font-medium">{executionTitle(item.operations[index]!, i18n.language)}</h3>}
      {runtimeResult || output && (item.operations[index]!.name === 'run.execute' || value == null) ? <ExecutionOutput output={output ?? { state: 'unavailable' }} invocation={item.operations[index]!} /> :
        <ExecutionResult invocation={item.operations[index]!} value={value!} />}
    </div>;
  })}</div>;
  const requestState = <>
    {focusedConnection && progress?.kind === 'authorize' && <p role="status" className="text-sm text-muted-foreground">{t('requestAuthorize', { name: service })}</p>}
    {!pending && (!focusedConnection || item.state !== 'succeeded' && !connectionCancelled) && <p role="status"><State value={
      connectionCancelled ? 'cancelled' : item.delivery?.state === 'expired' ? 'expired' : item.state
    } /></p>}
    {pending && !approvalAccepted && !progress && !item.canRespond && <p role="status" className="text-sm text-muted-foreground">{
      item.wait === 'execution' ? <State value="running" /> : t('requestWaitingForRecipient')
    }</p>}
  </>;
  if (focusedConnection && requestConnection) return <ConnectionRequestReview title={title}
    from={pending ? item.from.name : undefined}
    name={requestConnection.name !== service || !pending ? requestConnection.name : undefined}
    message={pending ? item.message : undefined}>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    {requestState}
    {form}
    {!account.principal && pending && <Button className={connectionRequestAction} asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + (item.delivery?.id ?? item.id))}>{t('signinToApprove')}</Link></Button>}
    {!pending && item.returnUrl && <Button className={connectionRequestAction + ' w-fit'} asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('retry')}</a></Button>}
  </ConnectionRequestReview>;
  const requestSummary = <>
    {pending && <p className="text-sm text-muted-foreground">{t('requestFrom', { name: item.from.name })}</p>}
    {pending && item.message && <p className="leading-relaxed whitespace-pre-wrap wrap-anywhere">{item.message}</p>}
    {item.proposal && <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p>}
    {requestState}
  </>;
  return <Page title={title} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    <RecipientAccessNotice principalId={account.principal?.id} id={item.id} />
    {!recipientRequest && <ResealingNotice principalId={account.principal?.id} requestId={pageId} />}
    {recipientRequest ? <Panel>{requestSummary}<ResealingNotice principalId={account.principal?.id} requestId={pageId} />{form}{output}</Panel> : <>
      <Panel>
        <Detail label={t('status')}><State value={requestMode ? item.delivery!.state : item.state} /></Detail>
        {!requestMode && item.operations.length === 1 && <Detail label={t('functionProgram')}>{executionTitle(item.operations[0]!, i18n.language)}</Detail>}
        <Detail label={t(requestMode ? 'requestedBy' : 'operationInitiator')}>{requestMode ? item.from.name : details.initiator.name}<Copy value={requestMode ? item.from.id : details.initiator.id} /></Detail>
        {requestMode && <Detail label={t('requestedTo')}>{item.to?.name ?? '—'}</Detail>}
        <Detail label={t('created')}><DateText value={item.createdAt} seconds /></Detail>
        {!requestMode && item.operations.length === 1 && details.steps[0] && <ExecutionFacts details={details.steps[0]} environments={details.environments} />}
        {pending && (requestMode || ['approval', 'input'].includes(item.wait ?? '')) && <Detail label={t('expires')}><DateText value={item.delivery?.expiresAt ?? item.expiresAt} /></Detail>}
        {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
          (item.message || requestMode) && <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
        {item.code && <Detail label={t('code')}>{item.code}<Copy value={item.code} /></Detail>}
        {requester && pending && <Detail label={t('url')}><Link className="underline underline-offset-4" to={new URL(shareUrl).pathname + new URL(shareUrl).hash}>{item.url}</Link><Copy value={shareUrl} /></Detail>}
        {item.delivery && <Detail label={t(requestMode ? 'execution' : 'requests')}><Link className="underline underline-offset-4" to={(requestMode ? '/executions/' + item.id : '/requests/' + item.delivery.id) + new URL(shareUrl).hash}>{t(requestMode ? 'executionOpen' : 'requestOpen')}</Link></Detail>}
      </Panel>
      {form}
      {output && <Panel title={t('result')}>
        {requestMode && <Detail label={t('status')}><State value={item.state} /></Detail>}
        {output}
      </Panel>}
    </>}
    {!account.principal && pending && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent((requestMode ? '/requests/' : '/executions/') + (item.delivery?.id ?? item.id))}>{t('signinToApprove')}</Link></Button>}
    {!pending && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('retry')}</a></Button>}
  </Page>;
}
