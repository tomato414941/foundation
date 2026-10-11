import { Form, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/invocation';
import { Invocation } from '../../../shared/function-api';
import { api, actionResult, signedIn } from '../api';
import { Button } from '../components/ui/button';
import { DateText, Detail, ErrorNotice, JsonView, Notice, Page, Panel, State, usePolling } from '../components';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api('/invocations/' + params.id, { signal: request.signal }, Invocation);
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(() => api('/invocations/' + params.id + '/cancel', { method: 'POST', body: {} }, Invocation));
}
export default function InvocationPage() {
  const data = useLoaderData<typeof clientLoader>(), action = useActionData<typeof clientAction>(), { t } = useTranslation();
  const active = ['queued', 'running'].includes(data.state);
  const cancelling = data.error?.code === 'cancellation_pending';
  usePolling(active || cancelling);
  return <Page title={t('result')} actions={active && <Form method="post">
    <Button type="submit" variant="destructive">{t('cancel')}</Button>
  </Form>}>
    <ErrorNotice error={action && typeof action.error === 'string' ? action.error : null} />
    <Panel>
      <Detail label={t('id')}>{data.id}</Detail>
      <Detail label={t('status')}><State value={cancelling ? 'stopping' : data.state} /></Detail>
      <Detail label={t('created')}><DateText value={data.createdAt} /></Detail>
    </Panel>
    {cancelling ? <Notice tone="info">{t('errors.cancellation_pending')}</Notice>
      : data.error && <ErrorNotice error={data.error.code} />}
    {data.state === 'succeeded' && <Panel title={t('executionOutput')}>
      {typeof data.result === 'string' ? <pre className="max-h-[480px] overflow-auto whitespace-pre-wrap wrap-anywhere">{data.result}</pre>
        : <JsonView value={data.result} />}
    </Panel>}
  </Page>;
}
