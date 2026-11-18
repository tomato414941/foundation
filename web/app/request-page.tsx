import { useEffect } from 'react';
import { Form, Link, redirect, redirectDocument, useActionData, useLoaderData, useLocation, useNavigation, useRevalidator, useRouteLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ArrowUpRight } from 'lucide-react';
import type { clientLoader as rootLoader } from './root';
import type { JsonValue } from '../../shared/contracts';
import { OperationView, RequestView } from '../../shared/operations';
import type { OperationCall, OperationRecordView, RequestRecordView } from '../../shared/operations';
import { atPointer } from '../../shared/values';
import { actionResult, api, ApiFailure, errorCode, formText, holdingKeys, session } from './api';
import { connectionClient, custodyClient, operationClient } from './custody';
import { getIdentity, requireKeys, resealNow, useResealing } from './keys';
import { ResealingNotice } from './resealing-notice';
import { RecipientAccessNotice } from './recipient-verification';
import { loadOperationForm, OperationInputFields, operationSubmission } from './operation-form';
import { ConnectionProgress } from './connection-progress';
import { ConnectionUsers } from './connection-users';
import { ConnectionRequestReview, connectionRequestAction } from './connection-request-review';
import { loadRequestConnection, requestConnectionMethod } from './request-connection';
import { DelegationReview, loadDelegationReviews } from './delegation-review';
import { loadOperationReviews, OperationNotes, OperationReview } from './operation-review';
import { OperationResult, operationTitle } from './operation-details';
import { Button } from './components/ui/button';
import { InputField, TextareaField } from './form-fields';
import { Copy, DateText, Detail, ErrorNotice, ExternalLink, Notice, Page, Panel, ProposalText, State, usePolling } from './components';

function substitute(value: JsonValue, approver: string, requester: string): JsonValue {
  if (value === '$approver') return approver;
  if (value === '$requester') return requester;
  if (Array.isArray(value)) return value.map(item => substitute(item, approver, requester));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, substitute(child, approver, requester)]));
  return value;
}
const resourceTransfer = (item: RequestRecordView) => item.operations.length === 1 && item.operations[0]?.name === 'resource.transfer';
// The operations an approval made, and how they stand together: made, still to be made, or stopped short.
function outcome(item: RequestRecordView) {
  if (item.state !== 'approved') return null;
  const states = item.performed.map(made => made.state);
  if (states.includes('in_progress')) return 'in_progress';
  if (states.includes('uncertain')) return 'uncertain';
  if (states.includes('failed')) return 'failed';
  if (states.includes('stopped')) return 'stopped';
  if (states.includes('cancelled')) return 'cancelled';
  return 'succeeded';
}
// The operation the approver's device makes with what it enters here: while the request waits, the first that seals what
// it saves; once approved, the first not made yet, when this browser may make it.
function inputOperation(item: RequestRecordView, next: OperationRecordView | null, approverId: string) {
  if (item.state === 'pending') {
    const index = item.operations.findIndex(operation => operation.keyholder);
    if (index < 0 || !item.canAnswer) return null;
    const { name, input } = item.operations[index]!;
    return { index, invocation: { name, input: substitute(input, approverId, item.from.id) } as OperationCall };
  }
  if (!next || !next.keyholder || next.state !== 'stopped' || !next.canPerform || !next.request) return null;
  return { index: next.request.position, invocation: { name: next.name, input: next.input } };
}
function configuration(invocation: OperationCall, input: OperationCall['input'], fields: string[]) {
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '' ||
      typeof input[key] === 'object' && !Array.isArray(input[key]) && JSON.stringify(invocation.input[key]) !== JSON.stringify(input[key])))
    .map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
// Lines that change who opens what a principal holds: once approved, this browser seals those items again.
const resealing = (item: RequestRecordView) => !item.proposal && item.operations.some(operation =>
  ['relation.draw', 'relation.erase'].includes(operation.name) && ['delegate', 'member'].includes(String(operation.input.relation)));
// The principal a line awaiting approval lets open what the approver holds, as its delegate or member.
function lineSubject(item: RequestRecordView, approverId: string) {
  const operation = item.proposal ? undefined : item.operations.find(operation => operation.name === 'relation.draw' &&
    ['delegate', 'member'].includes(String(operation.input.relation)));
  const subject = operation ? substitute(operation.input.subjectId ?? null, approverId, item.from.id) : null;
  return typeof subject === 'string' && subject !== approverId ? subject : null;
}
// Approving such a line has this browser seal for the subject at once, so the subject's public key is verified before,
// or by the fingerprint in the link the subject gave. While it is not, this names the subject. It reads what the
// approver verified, which needs the approver's private key in this browser.
async function unverifiedSubject(item: RequestRecordView, approverId: string, id: string) {
  const subject = lineSubject(item, approverId);
  if (!subject) return null;
  if (subject === item.from.id && sessionStorage.getItem('foundation.fingerprint.request.' + id)) return null;
  try { if (await (await custodyClient()).verifiedIdentity(subject)) return null; }
  catch (error) { if (error instanceof ApiFailure && error.code === 'key_binding_required') return null; throw error; }
  return subject === item.from.id ? item.from.name
    : await api<{ name: string }>('/identities/' + subject).then(identity => identity.name, () => subject);
}
type PageArgs = { params: { id?: string }; request: Request };
// The request with the operations its approval made, which those who may see the request may also see.
async function readItem(id: string, signal?: AbortSignal) {
  const item = await api('/requests/' + id, { signal }, RequestView);
  const made = await Promise.all(item.performed.map(entry => api('/operations/' + entry.id, { signal }, OperationView)));
  return { item, made, next: made.find(operation => operation.state !== 'succeeded') ?? null };
}
export async function clientLoader({ params, request }: PageArgs) {
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
  let read: Awaited<ReturnType<typeof readItem>>;
  try { read = await readItem(params.id!, request.signal); }
  catch (error) {
    if (!account.principal && error instanceof ApiFailure && [401, 403].includes(error.status))
      throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
    throw error;
  }
  const needsKeys = !read.item.operations.every(operation => operation.name === 'resource.transfer' && !operation.input.content);
  if (account.principal && !account.requestId && needsKeys) await holdingKeys(request, account.principal);
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError: string | null = read.next?.error?.code ?? null;
  if (read.next?.canPerform && read.next.continuation && !account.requestId) {
    const continuationId = read.next.continuation.id;
    try { progress = await (await connectionClient()).progress(continuationId); }
    catch (error) { operationError = errorCode(error); }
    read = await readItem(params.id!);
    if (read.next?.continuation?.id !== continuationId) { progress = null; operationError = read.next?.error?.code ?? null; }
  }
  const { item, made, next } = read;
  const current = inputOperation(item, next, account.principal?.id ?? '');
  const operation = item.operations.length === 1 ? item.operations[0] : null;
  const reviewContext = { approver: item.canAnswer ? account.principal : null, requester: item.from,
    principals: [...account.principals, item.from, ...(item.to ? [item.to] : [])],
    inspect: !!account.principal && !account.requestId, signal: request.signal };
  const [inputForm, requestConnection, delegationReviews, operationReviews] = await Promise.all([
    current && !account.requestId && !next?.continuation ? loadOperationForm(current.invocation) : null,
    operation?.name === 'connection.connect' && item.from.id !== account.principal?.id ? loadRequestConnection({ name: operation.name,
      input: substitute(operation.input, account.principal?.id ?? '', item.from.id) as OperationCall['input'] }, request.signal, !account.requestId) : null,
    item.state === 'pending' && !item.proposal ? loadDelegationReviews(item.operations, reviewContext) : [],
    item.state === 'pending' && !item.proposal ? loadOperationReviews(item.operations, reviewContext) : [],
  ]);
  const code = item.state === 'pending' && item.from.id === account.principal?.id
    ? sessionStorage.getItem('foundation.request.' + item.id) ?? undefined : undefined;
  if (!code) sessionStorage.removeItem('foundation.request.' + item.id);
  const unverified = account.principal && !account.requestId && item.canAnswer && await getIdentity(account.principal.id)
    ? await unverifiedSubject(item, account.principal.id, params.id!) : null;
  return { item, made, next, code, account, current, inputForm, progress, operationError, requestConnection, delegationReviews,
    operationReviews, unverified };
}
export async function clientAction({ params, request }: PageArgs) {
  return actionResult(async () => {
    const path = '/requests/' + params.id, form = await request.formData(), intent = formText(form, 'intent');
    let { item, next } = await readItem(params.id!);
    if (intent === 'decline' || intent === 'withdraw') {
      await api(path + '/' + intent, { method: 'POST', body: {} }, RequestView);
      return readItem(params.id!);
    }
    if (intent === 'cancel' && next) {
      await requireKeys();
      if (next.continuation) await (await connectionClient()).cancel(next.continuation.id);
      else await api('/operations/' + next.id + '/cancel', { method: 'POST', body: {} }, OperationView);
      return readItem(params.id!);
    }
    const account = await session(), approverId = account.principal!.id, current = inputOperation(item, next, approverId);
    // Approving with the fingerprint the requester linked first verifies its public key, for each of the approver's devices.
    const linked = intent === 'approve' ? new URLSearchParams(window.location.hash.slice(1)).get('fingerprint')
      ?? sessionStorage.getItem('foundation.fingerprint.request.' + params.id) : null;
    // Entering input, verifying a public key, and sealing items again for a changed line all use the private key, so a
    // passkey opens it first when this browser does not hold it, before anything is answered.
    if (current || linked || intent === 'approve' && resealing(item)) await requireKeys(approverId);
    const data = current ? await loadOperationForm(current.invocation) : null;
    const prepared = data ? operationSubmission(data, form) : null;
    const choices = current && prepared
      ? configuration(current.invocation, prepared.input, item.operations[current.index]!.configure) : {};
    if (intent === 'approve') {
      if (!linked && !account.requestId && await unverifiedSubject(item, approverId, params.id!))
        throw new ApiFailure('identity_untrusted');
      if (linked) await (await custodyClient()).trustIdentity(item.from.id, linked);
      const values = item.operations.map((operation, index) => Object.fromEntries(operation.inputs.filter(input => !input.secret).map((input, inputIndex) => {
        const key = `input.${index}.${inputIndex}`;
        return [input.pointer, String(form.has(key) ? form.get(key) : index === current?.index && prepared
          ? atPointer(prepared.input, input.pointer) ?? '' : '')];
      })));
      await api(path + '/approve', { method: 'POST', body: { values,
        configuration: item.operations.map((_operation, index) => index === current?.index ? choices : {}),
        code: formText(form, 'code') || undefined } }, RequestView);
      sessionStorage.removeItem('foundation.fingerprint.request.' + params.id);
      if (resealing(item)) await resealNow(approverId, params.id!);
      ({ item, next } = await readItem(params.id!));
    } else if (current && next && Object.keys(choices).length)
      await api('/operations/' + next.id, { method: 'PATCH', body: { values: choices } }, OperationView);
    // What this device seals for the approved request it makes now, with what was entered here.
    const waiting = current && next?.state === 'stopped' && next.request?.position === current.index ? next : null;
    if (current && waiting && prepared) {
      const progress = await (await operationClient()).continue(waiting.id, prepared.material);
      if (current.invocation.name === 'connection.connect' && 'kind' in progress && progress.kind === 'authorize' && !progress.device) {
        const method = await requestConnectionMethod(String(current.invocation.input.methodId));
        if (method.kind !== 'approval' && ['http:', 'https:'].includes(new URL(progress.url).protocol))
          return redirectDocument(progress.url);
      }
    }
    return readItem(params.id!);
  });
}
export default function RequestPage() {
  const { t, i18n } = useTranslation(), { item, made, next, code, account, current, inputForm, progress, operationError, requestConnection,
    delegationReviews, operationReviews, unverified } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const waiting = item.state === 'pending', status = outcome(item);
  // Still moving: waiting for its answer, or approved with operations still being made.
  const active = waiting || status === 'in_progress' || status === 'stopped';
  const requester = item.from.id === account.principal?.id;
  const transferring = resourceTransfer(item);
  const location = useLocation();
  const fingerprint = new URLSearchParams(location.hash.slice(1)).get('fingerprint')
    ?? sessionStorage.getItem('foundation.fingerprint.request.' + item.id);
  const shareUrl = item.url + (fingerprint ? '#fingerprint=' + encodeURIComponent(fingerprint) : '');
  const sealing = useResealing(account.principal?.id);
  const approvalAccepted = waiting && navigation.state !== 'idle' && sealing?.requestId === item.id;
  const root = useRouteLoaderData<typeof rootLoader>('root'), revalidator = useRevalidator();
  const needsKeys = !!current && !!account.requestId;
  const recipientRequest = !requester;
  const focusedConnection = !!requestConnection && !requester;
  const service = requestConnection?.method?.defaultName ?? requestConnection?.name ?? '';
  const connectionAction = requestConnection?.reconnecting ? 'reconnect' : 'connect';
  const connectionCancelled = ['declined', 'withdrawn'].includes(item.state) || status === 'cancelled';
  const connectionTitle = requestConnection?.reconnecting
    ? status === 'succeeded' ? 'requestReconnected' : item.state === 'declined' ? 'requestReconnectDeclined'
      : item.state === 'withdrawn' ? 'requestReconnectWithdrawn' : connectionCancelled ? 'requestReconnectCancelled' : 'requestReconnect'
    : status === 'succeeded' ? 'requestConnected' : item.state === 'declined' ? 'requestConnectDeclined'
      : item.state === 'withdrawn' ? 'requestConnectWithdrawn' : connectionCancelled ? 'requestConnectCancelled' : 'requestConnect';
  // Once a request is carried out, its heading says what was done, in the words it was asked in.
  const done = recipientRequest && !transferring && !focusedConnection && status === 'succeeded' && item.operations.length === 1 &&
    i18n.exists('done.' + item.operations[0]!.name) ? t('done.' + item.operations[0]!.name) : null;
  // A request that ended otherwise says how it ended, naming what was asked below.
  const ended = recipientRequest && !transferring && !focusedConnection && !active && status !== 'succeeded'
    ? item.state === 'expired' ? 'requestExpiredTitle' : item.state === 'declined' ? 'requestDeclinedTitle'
      : item.state === 'withdrawn' ? 'requestWithdrawnTitle' : status === 'failed' ? 'requestFailedTitle'
      : status === 'uncertain' ? 'requestUncertainTitle' : 'requestCancelledTitle' : null;
  const title = transferring ? t('transferTitle') : focusedConnection && service ? t(connectionTitle, { name: service })
    : focusedConnection ? t(connectionAction)
    : done ?? (ended ? t(ended) : null) ?? (recipientRequest && !item.proposal && item.operations.length === 1
      ? operationTitle(item.operations[0]!, i18n.language) : t('request'));
  // The steps show while the request waits, while this browser makes or authorizes one of its operations, and to its
  // requester when it asks for several.
  const showSteps = waiting || active && (!!current || !!progress) || !recipientRequest && item.operations.length > 1;
  const results = made.filter(operation => operation.state === 'succeeded' && operation.result !== null &&
    !(recipientRequest && operation.result && typeof operation.result === 'object' && !Array.isArray(operation.result) &&
      Object.keys(operation.result).length === 1 && operation.result.ok === true));
  // An operation that stopped short is made again, or the ones after it are continued, from its own page, by whoever
  // makes it; others are told it did not complete.
  const stopped = !waiting && next && (['failed', 'uncertain'].includes(next.state) || next.state === 'stopped' && next.canPerform) &&
    !current ? next : null;
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle') void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(active, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  const form = !approvalAccepted && showSteps && <Form method="post">
    <div className="flex min-w-0 flex-col gap-6">
      {!item.proposal && (waiting || item.operations.length > 1) && item.operations.map((operation, index) => {
        const Container = recipientRequest ? 'div' : Panel;
        const heading = item.operations.length > 1 ? `${index + 1}. ${operationTitle(operation, i18n.language)}` : operationTitle(operation, i18n.language);
        const state = item.performed.find(entry => entry.position === index)?.state;
        return <Container key={index} title={recipientRequest ? undefined : heading}>
          <div className="flex min-w-0 flex-col gap-4">
            {recipientRequest && item.operations.length > 1 && <h2 className="text-sm font-semibold">{heading}</h2>}
            {current?.index === index && inputForm && <OperationInputFields data={inputForm}
              requestPrincipalId={recipientRequest && (focusedConnection || operation.name === 'connection.authorize') ? account.principal?.id : undefined} />}
            {next?.request?.position === index && progress && !focusedConnection && <ConnectionProgress progress={progress} cancelIntent="cancel" />}
            {!operation.keyholder && waiting && (delegationReviews[index]
              ? <DelegationReview review={delegationReviews[index]} /> : operationReviews[index] && <OperationReview rows={operationReviews[index]} />)}
            {(!recipientRequest || item.operations.length > 1) && state && <Detail label={t('status')}><State value={state} /></Detail>}
            {waiting && !operation.keyholder && operation.inputs.filter(input => !input.secret).map((input, inputIndex) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
              {input.multiline ? <TextareaField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                disabled={!item.canAnswer} required={item.canAnswer} rows={3} /> :
                <InputField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                  disabled={!item.canAnswer} required={item.canAnswer} />}
              {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
            </div>)}
          </div>
        </Container>;
      })}
      {recipientRequest && waiting && <OperationNotes operations={item.operations} />}
      {focusedConnection && waiting && requestConnection?.usersConfigured && <ConnectionUsers users={requestConnection.users} review />}
      {focusedConnection && progress && <ConnectionProgress progress={progress} cancelIntent="cancel" review
        authorization={{ label: t('requestContinueAtService', { name: service }), newWindow: requestConnection?.method?.kind === 'approval' }} />}
      {waiting && item.canAnswer && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
      {needsKeys && <Notice tone="info" action={<Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signin')}</Link></Button>}>
        {t(recipientRequest ? 'requestSignInHelp' : 'signinForPrivateInput')}
      </Notice>}
      {unverified && <Notice tone="warning">{t('approvalUnverified', { name: unverified })}</Notice>}
      {(waiting && item.canAnswer || current && !waiting && !next?.continuation) && !needsKeys && <div className="flex flex-wrap items-center gap-4">
        <Button className={focusedConnection ? connectionRequestAction : transferring ? 'min-h-11 px-4' : undefined} type="submit" name="intent" value={waiting ? 'approve' : 'continue'}
          loading={navigation.state !== 'idle' && (focusedConnection || !['decline', 'withdraw', 'cancel'].includes(String(navigation.formData?.get('intent'))))}
          disabled={navigation.state !== 'idle' || (waiting && !!unverified)}>
          {focusedConnection ? requestConnection?.method?.registration.kind === 'authorization'
            ? t(requestConnection.reconnecting ? 'requestReconnectAtService' : 'requestConnectAtService', { name: service })
            : t(connectionAction)
            : t(waiting ? 'approve' : current?.invocation.name === 'connection.connect' ? 'connect' : 'save')}
          {focusedConnection && requestConnection?.method?.registration.kind === 'authorization' && <ArrowUpRight aria-hidden="true" />}
        </Button>
        {waiting && item.canAnswer && <Button className={focusedConnection ? 'min-h-12 px-4 text-muted-foreground' : transferring ? 'min-h-11 px-4 text-muted-foreground' : undefined} type="submit" name="intent" value="decline" formNoValidate variant="ghost" disabled={navigation.state !== 'idle'}>{t(transferring ? 'transferDecline' : 'decline')}</Button>}
        {recipientRequest && waiting && !focusedConnection && !transferring && <span className="text-sm text-muted-foreground">{t('expires')} <DateText value={item.expiresAt} /></span>}
      </div>}
      {item.canWithdraw && <Button type="submit" name="intent" value="withdraw" formNoValidate disabled={navigation.state !== 'idle'}
        variant={transferring ? 'ghost' : 'destructive'} className={transferring ? 'min-h-11 w-fit px-4 text-muted-foreground' : undefined}>
        {t('withdrawRequest')}
      </Button>}
    </div>
  </Form>;
  const output = !focusedConnection && results.length > 0 && <div className="flex min-w-0 flex-col gap-6">{results.map(operation =>
    <div key={operation.id} className="flex min-w-0 flex-col gap-4">
      {item.operations.length > 1 && <h3 className="text-sm font-medium">{operationTitle(operation, i18n.language)}</h3>}
      <OperationResult invocation={operation} value={operation.result!} />
    </div>)}</div>;
  // Who the request waits on, when the one viewing it cannot move it on.
  const waitingNotice = !approvalAccepted && !progress && (waiting && !item.canAnswer || status === 'stopped' && next && !next.canPerform) &&
    <p role="status" className="text-sm text-muted-foreground">{waiting ? t('requestWaitingForRecipient')
      : t('operationWaitingFor', { name: next!.actor.name })}</p>;
  const stoppedNotice = stopped && <Notice tone={stopped.state === 'stopped' ? 'info' : 'warning'}
    action={<Button asChild variant="outline"><Link to={'/operations/' + stopped.id}>{t('openOperation')}</Link></Button>}>
    {t(stopped.state === 'stopped' ? 'requestOperationStopped' : stopped.state === 'uncertain' ? 'requestOperationUncertain'
      : stopped.canPerform ? 'requestOperationFailed' : 'requestOperationIncomplete', { name: operationTitle(stopped, i18n.language) })}
  </Notice>;
  const requestState = <>
    {focusedConnection && progress?.kind === 'authorize' && !progress.device && <p role="status" className="text-sm text-muted-foreground">{t('requestAuthorize', { name: service })}</p>}
    {!active && !done && !ended && (!focusedConnection || status !== 'succeeded' && !connectionCancelled) && <p role="status"><State value={
      status ?? item.state} /></p>}
    {waitingNotice}
  </>;
  if (focusedConnection && requestConnection) return <ConnectionRequestReview title={title}
    from={waiting ? item.from.name : undefined}
    name={requestConnection.name !== service || !waiting ? requestConnection.name : undefined}
    message={waiting ? item.message : undefined}>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    {requestState}
    {stoppedNotice}
    {form}
    {!account.principal && waiting && <Button className={connectionRequestAction} asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signinToApprove')}</Link></Button>}
    {!active && item.returnUrl && <Button className={connectionRequestAction + ' w-fit'} asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'withdrawn'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('askAgain')}</a></Button>}
  </ConnectionRequestReview>;
  const requestSummary = <>
    {waiting && <p className="text-sm text-muted-foreground">{t('requestFrom', { name: item.from.name })}</p>}
    {(done || ended) && <p role="status" className="sr-only">{title}</p>}
    {ended && <p className="font-medium">{new Intl.ListFormat(i18n.language).format(item.operations.map(operation => operationTitle(operation, i18n.language)))}</p>}
    {waiting && item.message && <blockquote className="border-l-2 pl-3 leading-relaxed whitespace-pre-wrap wrap-anywhere">{item.message}</blockquote>}
    {item.proposal && <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p>}
    {requestState}
  </>;
  if (transferring && requester && waiting && item.proposal?.kind === 'transfer') return <Page title={title} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    <Panel>
      <p role="status" className="font-medium">{t('transferAwaitingRecipient', { name: item.proposal.to.name })}</p>
      <p className="leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p>
      <div className="flex min-w-0 flex-col gap-2">
        <p className="text-sm text-muted-foreground">{t('transferShareLink', { name: item.proposal.to.name })}</p>
        <div className="flex min-w-0 items-start gap-2">
          <Link className="min-w-0 break-all text-sm underline underline-offset-4" to={new URL(shareUrl).pathname + new URL(shareUrl).hash}>{shareUrl}</Link>
          <Copy value={shareUrl} />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">{t('expires')} <DateText value={item.expiresAt} /></p>
      {form}
    </Panel>
    <RecipientAccessNotice principalId={account.principal?.id} id={item.id} />
  </Page>;
  return <Page title={title} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    <RecipientAccessNotice principalId={account.principal?.id} id={item.id} />
    {!recipientRequest && <ResealingNotice principalId={account.principal?.id} requestId={item.id} />}
    {stoppedNotice}
    {recipientRequest ? <Panel>{requestSummary}<ResealingNotice principalId={account.principal?.id} requestId={item.id} />{form}{output}
      {status === 'succeeded' && <OperationNotes operations={item.operations} done />}</Panel> : <>
      <Panel>
        <Detail label={t('status')}><State value={item.state} /></Detail>
        <Detail label={t('requestedBy')}>{item.from.name}<Copy value={item.from.id} /></Detail>
        <Detail label={t('requestedTo')}>{item.to?.name ?? '—'}</Detail>
        <Detail label={t('created')}><DateText value={item.createdAt} seconds /></Detail>
        {waiting && <Detail label={t('expires')}><DateText value={item.expiresAt} /></Detail>}
        {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
          <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
        {code && <Detail label={t('code')}>{code}<Copy value={code} /></Detail>}
        {requester && waiting && <Detail label={t('url')}><Link className="underline underline-offset-4" to={new URL(shareUrl).pathname + new URL(shareUrl).hash}>{item.url}</Link><Copy value={shareUrl} /></Detail>}
        {waitingNotice}
      </Panel>
      {form}
      {made.length > 0 && <Panel title={t('performedOperations')}>
        <ul className="flex min-w-0 flex-col gap-3">{made.map(operation => <li key={operation.id} className="flex min-w-0 flex-wrap items-center gap-3">
          <Link className="underline underline-offset-4 wrap-anywhere" to={'/operations/' + operation.id}>{operationTitle(operation, i18n.language)}</Link>
          <State value={operation.state} />
        </li>)}</ul>
        {output}
      </Panel>}
    </>}
    {!account.principal && waiting && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signinToApprove')}</Link></Button>}
    {!active && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'withdrawn'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('askAgain')}</a></Button>}
  </Page>;
}
