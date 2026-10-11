import { useEffect } from 'react';
import { Form, Link, useActionData, useLoaderData, useNavigation, useRevalidator, useRouteLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/request';
import type { clientLoader as rootLoader } from '../root';
import { ApprovalRequest } from '../../../shared/contracts';
import type { ApprovalView, JsonValue } from '../../../shared/contracts';
import type { OperationInvocation } from '../../../shared/operations';
import { atPointer } from '../../../shared/values';
import { actionResult, api, errorCode, formText, session } from '../api';
import { connectionClient, operationClient } from '../custody';
import { loadOperationForm, OperationInputFields, operationSubmission } from '../operation-form';
import { ConnectionProgress } from '../connection-progress';
import { Button } from '../components/ui/button';
import { InputField, TextareaField } from '../form-fields';
import { Copy, DateText, Detail, ErrorNotice, ExternalLink, JsonView, Notice, Page, Panel, ProposalText, State, usePolling } from '../components';

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
  const invocation = item.operations[index]!.invocation!;
  return { index, invocation: { name: invocation.name, input: substitute(invocation.input, actorId, item.from.id) } as OperationInvocation };
}
function configuration(invocation: OperationInvocation, input: OperationInvocation['input']) {
  const fields = invocation.name === 'connection.connect' ? ['environmentId', 'name', 'appId', 'clientId'] :
    invocation.name === 'run.execute' ? ['environmentId'] : ['environmentIds', 'name', 'clientId'];
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '')).map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const fragment = new URLSearchParams(window.location.hash.slice(1)), token = fragment.get('token');
  if (token) {
    await api(`/requests/${params.id}/redeem`, { method: 'POST', body: { token } });
    history.replaceState(null, '', window.location.pathname);
  }
  let [item, account] = await Promise.all([api('/requests/' + params.id, { signal: request.signal }, ApprovalRequest), session(request)]);
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError: string | null = null;
  if (item.canRespond && !account.requestId && item.waiting?.continuation) {
    const continuationId = item.waiting.continuation.id;
    try {
      if (item.waiting.continuation.kind === 'connection') progress = await (await connectionClient()).progress(item.waiting.continuation.id);
      else await (await operationClient()).continue(item.id);
    } catch (error) { operationError = errorCode(error); }
    item = await api('/requests/' + params.id, {}, ApprovalRequest);
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
  return { item, account, current, inputForm, progress, operationError };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), intent = formText(form, 'intent');
    let item = await api('/requests/' + params.id, {}, ApprovalRequest);
    if (intent === 'cancel' || intent === 'decline') {
      if (intent === 'decline' && item.waiting?.continuation?.kind === 'connection')
        await (await connectionClient()).cancel(item.waiting.continuation.id);
      return api('/requests/' + params.id + '/' + intent, { method: 'POST', body: {} }, ApprovalRequest);
    }
    if (intent === 'acceptConnection') {
      if (item.waiting?.continuation?.kind !== 'connection') throw new Error('Continue the pending connection.');
      await (await connectionClient()).accept(item.waiting.continuation.id);
      return api('/requests/' + params.id, {}, ApprovalRequest);
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
        ? configuration(current.invocation, prepared.input) : {});
      item = await api('/requests/' + params.id + '/approve', { method: 'POST',
        body: { values, configuration: choices, code: formText(form, 'code') || undefined } }, ApprovalRequest);
    } else if (prepared && current) await (await operationClient()).configure(item.id, configuration(current.invocation, prepared.input));
    if (item.waiting && prepared) await (await operationClient()).continue(item.id, prepared.material);
    return api('/requests/' + params.id, {}, ApprovalRequest);
  });
}
export default function RequestPage() {
  const { t, i18n } = useTranslation(), { item, account, current, inputForm, progress, operationError } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  const pending = ['pending', 'running'].includes(item.state), requester = item.from.id === account.principal?.id;
  const root = useRouteLoaderData<typeof rootLoader>('root'), revalidator = useRevalidator();
  const needsKeys = !!current && !!account.requestId;
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle') void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(pending, progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  return <Page title={t('requests')} narrow>
    <ErrorNotice error={result && 'error' in result ? result.error : operationError} />
    <Panel>
      <Detail label={t('status')}><State value={item.state} /></Detail>
      <Detail label={t('requestedBy')}>{item.from.name}<Copy value={item.from.id} /></Detail>
      <Detail label={t('requestedTo')}>{item.to?.name ?? '—'}</Detail>
      <Detail label={t('expires')}><DateText value={item.expiresAt} /></Detail>
      {item.proposal ? <p className="font-medium leading-relaxed wrap-anywhere"><ProposalText proposal={item.proposal} /></p> :
        <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>}
      {item.code && <Detail label={t('code')}>{item.code}<Copy value={item.code} /></Detail>}
      {requester && <Detail label={t('url')}>{item.url}<Copy value={item.url} /></Detail>}
    </Panel>
    <Form method="post">
      <div className="flex min-w-0 flex-col gap-6">
        {!item.proposal && item.operations.map((operation, index) => {
          const privateOperation = operation.execution === 'keyholder';
          return <Panel key={index} title={`${index + 1}. ${i18n.language === 'ja' ? operation.title.ja : operation.title.en}`}>
            {current?.index === index && inputForm && <OperationInputFields data={inputForm} />}
            {item.waiting?.index === index && progress && <ConnectionProgress progress={progress} acceptIntent="acceptConnection" cancelIntent="decline" />}
            {!privateOperation && operation.body != null && <JsonView value={operation.body} />}
            {!privateOperation && operation.inputs.filter(input => !input.secret).map((input, inputIndex) => <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
              {input.multiline ? <TextareaField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                disabled={!item.canRespond || !pending} required={item.canRespond && pending} rows={3} /> :
                <InputField name={`input.${index}.${inputIndex}`} label={input.label} autoComplete="off"
                  disabled={!item.canRespond || !pending} required={item.canRespond && pending} />}
              {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
            </div>)}
          </Panel>;
        })}
        {pending && item.canRespond && !item.to && <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />}
        {needsKeys && <Notice tone="info" action={<Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signin')}</Link></Button>}>
          {t('signinForPrivateInput')}
        </Notice>}
        {pending && item.canRespond && !needsKeys && !item.waiting?.continuation && (item.state === 'pending' || current) && <div className="flex flex-wrap items-center gap-4">
          <Button type="submit" name="intent" value={item.state === 'pending' ? 'approve' : 'continue'} disabled={navigation.state !== 'idle'}>
            {t(item.state === 'pending' ? 'approve' : current?.invocation.name === 'connection.connect' ? 'connect' : 'save')}
          </Button>
          <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('decline')}</Button>
        </div>}
        {pending && requester && <Button type="submit" name="intent" value="cancel" formNoValidate variant="destructive">{t('cancelRequest')}</Button>}
        {item.state === 'running' && item.canRespond && !current && <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">{t('decline')}</Button>}
      </div>
    </Form>
    {!account.principal && pending && <Button asChild><Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>{t('signinToApprove')}</Link></Button>}
    {!pending && item.returnUrl && <Button asChild><a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a></Button>}
    {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && <Button variant="ghost" asChild><a href={item.refreshUrl}>{t('retry')}</a></Button>}
  </Page>;
}
