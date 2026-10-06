import { Button } from '../components/ui/button';
import { Form, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/run';
import { Run } from '../../../shared/contracts';
import { actionResult, api, signedIn } from '../api';
import { DateText, Detail, ErrorNotice, JsonView, Page, Panel, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api('/runs/' + params.id, { signal: request.signal }, Run);
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () =>
    api('/runs/' + params.id + '/cancel', { method: 'POST', body: {} }, Run),
  );
}
export default function RunPage() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
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
      {data.result !== null && (
        <Panel>
          <JsonView value={data.result} />
        </Panel>
      )}
    </Page>
  );
}
