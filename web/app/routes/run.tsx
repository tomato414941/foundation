import { Button } from '../components/ui/button';
import { Form, Link, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/run';
import { Task } from '../../../shared/execution';
import { actionResult, api, errorCode, signedIn } from '../api';
import { custodyClient } from '../custody';
import { DateText, Detail, ErrorNotice, JsonView, Notice, Page, Panel, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const task = await api('/executions/' + params.id, { signal: request.signal }, Task);
  try { return { task, decrypted: task.receipt ? await (await custodyClient()).result(task) : null, decryptError: null }; }
  catch (error) { return { task, decrypted: null, decryptError: errorCode(error) }; }
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () =>
    api('/executions/' + params.id + '/cancel', { method: 'POST', body: {} }, Task),
  );
}
export default function RunPage() {
  const { t } = useTranslation();
  const { task: data, decrypted, decryptError } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  usePolling(['queued', 'running'].includes(data.state));
  return (
    <Page
      title={t('result')}
      actions={
        ['queued', 'running'].includes(data.state) && (
          <Form method="post">
            <Button type="submit" variant="destructive">
              {t('cancel')}
            </Button>
          </Form>
        )
      }
    >
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel>
        <Detail label={t('id')}>{data.id}</Detail>
        <Detail label={t('status')}>
          <State value={data.state} />
        </Detail>
        <Detail label={t('created')}>
          <DateText value={data.createdAt} />
        </Detail>
      </Panel>
      {data.error && <ErrorNotice error={data.error} />}
      {decryptError && <Notice tone="info"><ErrorNotice error={decryptError} /><Link to="/account">{t('unlock')}</Link></Notice>}
      {decrypted?.error && <ErrorNotice error={decrypted.error.code} />}
      {decrypted?.result !== null && decrypted?.result !== undefined && (
        <Panel>
          <JsonView value={decrypted.result} />
        </Panel>
      )}
    </Page>
  );
}
