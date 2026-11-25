import { Form, Link, redirect, redirectDocument, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import { ArrowUpRight } from 'lucide-react';
import type { JsonValue } from '../../shared/contracts';
import { OperationView, RequestView } from '../../shared/operations';
import type { OperationCall, OperationRecordView, RequestRecordView } from '../../shared/operations';
import { atPointer } from '../../shared/values';
import { actionResult, api, ApiFailure, errorCode, formText, holdingKeys, session } from './api';
import { connectionClient, operationClient } from './custody';
import { requireKeys, resealNow, useResealing } from './keys';
import { ResealingNotice } from './resealing-notice';
import { loadOperationForm, OperationInputFields, operationSubmission } from './operation-form';
import { ConnectionProgress } from './connection-progress';
import { ConnectionUsers } from './connection-users';
import { ConnectionRequestReview, connectionRequestAction } from './connection-request-review';
import { loadRequestConnection, requestConnectionMethod } from './request-connection';
import { DelegationReview, loadDelegationReview } from './delegation-review';
import { reviewer, OperationReview } from './operation-review';
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
function inputOperation(item: RequestRecordView, made: OperationRecordView | null, approverId: string): OperationCall | null {
  const { operation } = item;
  if (item.state === 'pending' && item.canAnswer && operation.keyholder)
    return { name: operation.name, input: substitute(operation.input, approverId, item.from.id) as OperationCall['input'] };
  return made?.keyholder && made.canPerform && made.state === 'stopped' ? { name: made.name, input: made.input } : null;
}
function configuration(invocation: OperationCall, input: OperationCall['input'], fields: string[]) {
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '' ||
      typeof input[key] === 'object' && !Array.isArray(input[key]) && JSON.stringify(invocation.input[key]) !== JSON.stringify(input[key])))
    .map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
// Approvals that let someone open what the approver holds: once approved, this browser seals those items for them.
const resealing = ({ proposal, operation }: RequestRecordView) => !proposal && (
  operation.name === 'connection.authorize' ||
  operation.name === 'connection.connect' && Array.isArray(operation.input.users) && operation.input.users.length > 0 ||
  operation.name === 'relation.draw' && ['delegate', 'member', 'revealer', 'editor'].includes(String(operation.input.relation)));
type PageArgs = { params: { id?: string }; request: Request };
// Read the operation if the request has been approved.
async function readItem(id: string, signal?: AbortSignal) {
  const item = await api('/requests/' + id, { signal }, RequestView);
  const made = item.performed ? await api('/operations/' + item.performed.id, { signal }, OperationView) : null;
  return { item, made };
}
export async function clientLoader({ params, request }: PageArgs) {
  const account = await session(request);
  let read: Awaited<ReturnType<typeof readItem>>;
  try { read = await readItem(params.id!, request.signal); }
  catch (error) {
    if (!account.principal && error instanceof ApiFailure && [401, 403].includes(error.status))
      throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
    throw error;
  }
  const needsKeys = read.item.operation.name !== 'resource.transfer' || !!read.item.operation.input.content;
  if (account.principal && needsKeys) await holdingKeys(request, account.principal);
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError: string | null = read.made?.error?.code ?? null;
  if (read.made?.canPerform && read.made.continuation) {
    const continuationId = read.made.continuation.id;
    try { progress = await (await connectionClient()).progress(continuationId); }
    catch (error) { operationError = errorCode(error); }
    read = await readItem(params.id!);
    if (read.made?.continuation?.id !== continuationId) { progress = null; operationError = read.made?.error?.code ?? null; }
  }
  const { item, made } = read;
  const current = inputOperation(item, made, account.principal?.id ?? '');
  const { operation } = item;
  const review = item.state === 'pending' && !item.proposal && !operation.keyholder;
  const reviewContext = { approver: item.canAnswer ? account.principal : null, requester: item.from,
    principals: [...account.principals, item.from, ...(item.to ? [item.to] : [])],
    inspect: !!account.principal, signal: request.signal };
  const [inputForm, requestConnection, delegationReview, operationReview] = await Promise.all([
    current && !made?.continuation ? loadOperationForm(current) : null,
    operation.name === 'connection.connect' && item.from.id !== account.principal?.id ? loadRequestConnection({ name: operation.name,
      input: substitute(operation.input, account.principal?.id ?? '', item.from.id) as OperationCall['input'] }, request.signal) : null,
    review ? loadDelegationReview(operation, reviewContext) : null,
    review ? reviewer(reviewContext)(operation.input) : null,
  ]);
  return { item, made, account, current, inputForm, progress, operationError, requestConnection, delegationReview,
    operationReview };
}
export async function clientAction({ params, request }: PageArgs) {
  return actionResult(async () => {
    const path = '/requests/' + params.id, form = await request.formData(), intent = formText(form, 'intent');
    let { item, made } = await readItem(params.id!);
    if (intent === 'decline' || intent === 'withdraw') {
      await api(path + '/' + intent, { method: 'POST', body: {} }, RequestView);
      return readItem(params.id!);
    }
    if (intent === 'cancel' && made) {
      await requireKeys();
      if (made.continuation) await (await connectionClient()).cancel(made.continuation.id);
      else await api('/operations/' + made.id + '/cancel', { method: 'POST', body: {} }, OperationView);
      return readItem(params.id!);
    }
    const account = await session(), approverId = account.principal!.id, current = inputOperation(item, made, approverId);
    // Entering input and sealing items for someone let in both use the private key, so a passkey opens it first when this
    // browser does not hold it, before anything is answered.
    if (current || intent === 'approve' && resealing(item)) await requireKeys(approverId);
    const data = current ? await loadOperationForm(current) : null;
    const prepared = data ? operationSubmission(data, form) : null;
    const choices = current && prepared
      ? configuration(current, prepared.input, item.operation.configure) : {};
    if (intent === 'approve') {
      const fields = item.operation.inputs.filter(input => !input.secret);
      const values = Object.fromEntries(fields.map((input, index) => {
        const key = `input.${index}`;
        return [input.pointer, String(form.has(key) ? form.get(key) : prepared ? atPointer(prepared.input, input.pointer) ?? '' : '')];
      }));
      await api(path + '/approve', { method: 'POST', body: { values, configuration: choices, code: formText(form, 'code') || undefined } }, RequestView);
      if (resealing(item)) await resealNow(approverId, params.id!);
      ({ item, made } = await readItem(params.id!));
    } else if (current && made && Object.keys(choices).length)
      await api('/operations/' + made.id, { method: 'PATCH', body: { values: choices } }, OperationView);
    // What this device seals for the approved request it makes now, with what was entered here.
    if (current && prepared && made?.state === 'stopped' && made.canPerform) {
      const progress = await (await operationClient()).continue(made.id, prepared.material);
      if (current.name === 'connection.connect' && 'kind' in progress && progress.kind === 'authorize' && !progress.device) {
        const method = await requestConnectionMethod(String(current.input.methodId));
        if (method.kind !== 'approval' && ['http:', 'https:'].includes(new URL(progress.url).protocol))
          return redirectDocument(progress.url);
      }
    }
    return readItem(params.id!);
  });
}
export default function RequestPage() {
  const { t, i18n } = useTranslation(), { item, made, account, current, inputForm, progress, operationError, requestConnection,
    delegationReview, operationReview } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const { operation } = item, waiting = item.state === 'pending', status = made?.state;
  const active = waiting || status === 'in_progress' || status === 'stopped';
  const requester = item.from.id === account.principal?.id;
  const transferring = operation.name === 'resource.transfer';
  const shareUrl = item.url;
  const sealing = useResealing(account.principal?.id);
  const approvalAccepted = waiting && navigation.state !== 'idle' && sealing?.requestId === item.id;
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
  const done = recipientRequest && !transferring && !focusedConnection && status === 'succeeded' &&
    i18n.exists('done.' + operation.name) ? t('done.' + operation.name) : null;
  // A request that ended otherwise says how it ended, naming what was asked below.
  const ended = recipientRequest && !transferring && !focusedConnection && !active && status !== 'succeeded'
    ? item.state === 'expired' ? 'requestExpiredTitle' : item.state === 'declined' ? 'requestDeclinedTitle'
      : item.state === 'withdrawn' ? 'requestWithdrawnTitle' : status === 'failed' ? 'requestFailedTitle'
      : status === 'uncertain' ? 'requestUncertainTitle' : status === 'cancelled' ? 'requestCancelledTitle' : null : null;
  const title = transferring ? t('transferTitle') : focusedConnection && service ? t(connectionTitle, { name: service })
    : focusedConnection ? t(connectionAction)
    : done ?? (ended ? t(ended) : null) ?? (recipientRequest && !item.proposal
      ? operationTitle(operation, i18n.language) : t('request'));
  const showForm = waiting || active && (!!current || !!progress);
  const Container = recipientRequest ? 'div' : Panel;
  const stopped = !waiting && made && (['failed', 'uncertain'].includes(made.state) || made.state === 'stopped' && made.canPerform) &&
    !current ? made : null;
  usePolling(active, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  const form = !approvalAccepted && showForm && <Form method="post">
    <div className="flex min-w-0 flex-col gap-6">
      {!item.proposal && <Container title={recipientRequest ? undefined : operationTitle(operation, i18n.language)}>
        <div className="flex min-w-0 flex-col gap-4">
          {inputForm && <OperationInputFields data={inputForm}
            requestPrincipalId={recipientRequest && focusedConnection ? account.principal?.id : undefined} />}
          {progress && !focusedConnection && <ConnectionProgress progress={progress} cancelIntent="cancel" />}
          {delegationReview ? <DelegationReview review={delegationReview} /> : operationReview && <OperationReview rows={operationReview} />}
          {waiting && !operation.keyholder && operation.name === 'connection.authorize' && <p className="text-sm leading-relaxed text-muted-foreground">{t('requestConnectionAccess')}</p>}
          {waiting && !operation.keyholder && operation.inputs.filter(input => !input.secret).map((input, index) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
            {input.multiline ? <TextareaField name={`input.${index}`} label={input.label} autoComplete="off"
              disabled={!item.canAnswer} required={item.canAnswer} rows={3} /> :
              <InputField name={`input.${index}`} label={input.label} autoComplete="off"
                disabled={!item.canAnswer} required={item.canAnswer} />}
            {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
          </div>)}
        </div>
      </Container>}
      {focusedConnection && waiting && requestConnection?.usersConfigured && <ConnectionUsers users={requestConnection.users} />}
      {focusedConnection && progress && <ConnectionProgress progress={progress} cancelIntent="cancel" review
        authorization={{ label: t('requestContinueAtService', { name: service }), newWindow: requestConnection?.method?.kind === 'approval' }} />}
      {waiting && item.canAnswer && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
      {(waiting && item.canAnswer || current && !waiting && !made?.continuation) && <div className="flex flex-wrap items-center gap-4">
        <Button className={focusedConnection ? connectionRequestAction : transferring ? 'min-h-11 px-4' : undefined} type="submit" name="intent" value={waiting ? 'approve' : 'continue'}
          loading={navigation.state !== 'idle' && (focusedConnection || !['decline', 'withdraw', 'cancel'].includes(String(navigation.formData?.get('intent'))))}
          disabled={navigation.state !== 'idle'}>
          {focusedConnection ? requestConnection?.method?.registration.kind === 'authorization'
            ? t(requestConnection.reconnecting ? 'requestReconnectAtService' : 'requestConnectAtService', { name: service })
            : t(connectionAction)
            : t(waiting ? 'approve' : current?.name === 'connection.connect' ? 'connect' : 'save')}
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
  const value = made?.result;
  const acknowledgement = value && typeof value === 'object' && !Array.isArray(value) && value.ok === true && Object.keys(value).length === 1;
  const output = !focusedConnection && made?.state === 'succeeded' && value != null && !(recipientRequest && acknowledgement) &&
    <OperationResult invocation={made} value={value} />;
  // Who the request waits on, when the one viewing it cannot move it on.
  const waitingNotice = !approvalAccepted && !progress && (waiting && !item.canAnswer || status === 'stopped' && made && !made.canPerform) &&
    <p role="status" className="text-sm text-muted-foreground">{waiting ? t('requestWaitingForRecipient')
      : t('operationWaitingFor', { name: made!.actor.name })}</p>;
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
    {ended && <p className="font-medium">{operationTitle(operation, i18n.language)}</p>}
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
  </Page>;
  return <Page title={title} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    {!recipientRequest && <ResealingNotice principalId={account.principal?.id} requestId={item.id} />}
    {stoppedNotice}
    {recipientRequest ? <Panel>{requestSummary}<ResealingNotice principalId={account.principal?.id} requestId={item.id} />{form}{output}</Panel> : <>
      <Panel>
        <Detail label={t('status')}><State value={item.state} /></Detail>
        <Detail label={t('requestedBy')}>{item.from.name}<Copy value={item.from.id} /></Detail>
        <Detail label={t('requestedTo')}>{item.to?.name ?? '—'}</Detail>
        <Detail label={t('created')}><DateText value={item.createdAt} seconds /></Detail>
        {waiting && <Detail label={t('expires')}><DateText value={item.expiresAt} /></Detail>}
        {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
          <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
        {requester && waiting && <Detail label={t('url')}><Link className="underline underline-offset-4" to={new URL(shareUrl).pathname + new URL(shareUrl).hash}>{item.url}</Link><Copy value={shareUrl} /></Detail>}
        {waitingNotice}
      </Panel>
      {form}
      {made && <Panel title={t('performedOperation')}>
        <div className="flex min-w-0 flex-wrap items-center gap-3">
          <Link className="underline underline-offset-4 wrap-anywhere" to={'/operations/' + made.id}>{operationTitle(made, i18n.language)}</Link>
          <State value={made.state} />
        </div>
        {output}
      </Panel>}
    </>}
    {!account.principal && waiting && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signinToApprove')}</Link></Button>}
    {!active && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'withdrawn'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('askAgain')}</a></Button>}
  </Page>;
}
