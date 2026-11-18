import { Form, Link, redirect, redirectDocument, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { JsonValue } from '../../shared/contracts';
import { OperationView } from '../../shared/operations';
import type { OperationCall } from '../../shared/operations';
import { actionResult, api, ApiFailure, errorCode, formText, holdingKeys, session } from './api';
import { connectionClient, operationClient } from './custody';
import { requireKeys } from './keys';
import { loadOperationForm, OperationInputFields, operationSubmission } from './operation-form';
import { ConnectionProgress } from './connection-progress';
import { requestConnectionMethod } from './request-connection';
import { OperationResult, operationTitle } from './operation-details';
import { Button } from './components/ui/button';
import { Copy, DateText, Detail, ErrorNotice, Page, Panel, State, usePolling } from './components';

type PageArgs = { params: { id?: string }; request: Request };
function configuration(invocation: OperationCall, input: OperationCall['input'], fields: string[]) {
  return Object.fromEntries(fields.filter(key => input[key] !== undefined &&
    (invocation.input[key] == null || invocation.input[key] === '' ||
      typeof input[key] === 'object' && !Array.isArray(input[key]) && JSON.stringify(invocation.input[key]) !== JSON.stringify(input[key])))
    .map(key => [key, input[key]!])) as Record<string, JsonValue>;
}
const read = (id: string, signal?: AbortSignal) => api('/operations/' + id, { signal }, OperationView);
export async function clientLoader({ params, request }: PageArgs) {
  const account = await session(request);
  if (!account.principal) throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
  let item = await read(params.id!, request.signal);
  if (item.keyholder && item.canPerform) await holdingKeys(request, account.principal);
  let progress: Awaited<ReturnType<Awaited<ReturnType<typeof connectionClient>>['progress']>> | null = null;
  let operationError = item.error?.code ?? null;
  if (item.canPerform && item.continuation) {
    const continuationId = item.continuation.id;
    try { progress = await (await connectionClient()).progress(continuationId); }
    catch (error) { operationError = errorCode(error); }
    item = await read(params.id!);
    if (item.continuation?.id !== continuationId) { progress = null; operationError = item.error?.code ?? null; }
  }
  // An operation sealed on this device is made with what is entered here.
  const inputForm = item.canPerform && item.keyholder && !item.continuation
    ? await loadOperationForm({ name: item.name, input: item.input }) : null;
  return { item, progress, operationError, inputForm };
}
export async function clientAction({ params, request }: PageArgs) {
  return actionResult(async () => {
    const form = await request.formData(), intent = formText(form, 'intent'), item = await read(params.id!);
    if (intent === 'cancel') {
      if (item.continuation) { await requireKeys(); await (await connectionClient()).cancel(item.continuation.id); }
      else await api('/operations/' + item.id + '/cancel', { method: 'POST', body: {} }, OperationView);
      return read(params.id!);
    }
    if (intent !== 'perform') throw new ApiFailure('invalid_input');
    if (!item.keyholder) {
      await api('/operations/' + item.id + '/perform', { method: 'POST', body: {} });
      return read(params.id!);
    }
    await requireKeys();
    const invocation = { name: item.name, input: item.input }, prepared = operationSubmission(await loadOperationForm(invocation), form);
    const choices = configuration(invocation, prepared.input, item.configure);
    if (Object.keys(choices).length) await api('/operations/' + item.id, { method: 'PATCH', body: { values: choices } }, OperationView);
    const progress = await (await operationClient()).continue(item.id, prepared.material);
    if (item.name === 'connection.connect' && 'kind' in progress && progress.kind === 'authorize' && !progress.device) {
      const method = await requestConnectionMethod(String(item.input.methodId));
      if (method.kind !== 'approval' && ['http:', 'https:'].includes(new URL(progress.url).protocol))
        return redirectDocument(progress.url);
    }
    return read(params.id!);
  });
}
export default function OperationPage() {
  const { t, i18n } = useTranslation(), { item, progress, operationError, inputForm } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>(), navigation = useNavigation();
  usePolling(item.state === 'in_progress', progress?.kind === 'pending' || progress?.kind === 'authorize' ? 2000 : 5000);
  return <Page title={operationTitle(item, i18n.language)} narrow>
    <ErrorNotice error={result && 'error' in result && typeof result.error === 'string' ? result.error : operationError} />
    <Panel>
      <Detail label={t('status')}><State value={item.state} /></Detail>
      <Detail label={t('operationActor')}>{item.actor.name}<Copy value={item.actor.id} /></Detail>
      <Detail label={t('created')}><DateText value={item.createdAt} seconds /></Detail>
      {item.updatedAt !== item.createdAt && <Detail label={t('updated')}><DateText value={item.updatedAt} seconds /></Detail>}
      {item.request && <Detail label={t('request')}><Link className="underline underline-offset-4" to={'/requests/' + item.request.id}>{t('openRequest')}</Link></Detail>}
    </Panel>
    {item.state === 'succeeded' && item.result !== null && <Panel title={t('result')}>
      <OperationResult invocation={item} value={item.result} />
    </Panel>}
    {(item.canPerform || item.canCancel) && <Form method="post">
      <div className="flex min-w-0 flex-col gap-6">
        {inputForm && <OperationInputFields data={inputForm} />}
        {progress && <ConnectionProgress progress={progress} cancelIntent="cancel" />}
        {!progress && <div className="flex flex-wrap items-center gap-4">
          {item.canPerform && <Button type="submit" name="intent" value="perform" loading={navigation.state !== 'idle' && navigation.formData?.get('intent') === 'perform'}
            disabled={navigation.state !== 'idle'}>{t(item.state === 'stopped' ? 'continueOperation' : 'retry')}</Button>}
          {item.canCancel && <Button type="submit" name="intent" value="cancel" formNoValidate variant="ghost" disabled={navigation.state !== 'idle'}>
            {t('stopOperation')}</Button>}
        </div>}
      </div>
    </Form>}
  </Page>;
}
