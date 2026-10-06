import { Button } from '../components/ui/button';
import { Form, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/service-review';
import type { JsonValue } from '../../../shared/contracts';
import { actionResult, api, formText, safeReturn, session } from '../api';
import { ErrorNotice, JsonView, Page, Panel } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const current = await session(request);
  if (!current.principal)
    throw redirect('/signin?returnTo=' + encodeURIComponent(new URL(request.url).pathname));
  return api<{
    before: JsonValue;
    after: JsonValue;
  }>('/connections/' + params.id + '/review');
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const result = await api<{
      returnTo?: string;
    }>('/connections/' + params.id + '/review', {
      method: 'POST',
      body: { accept: formText(form, 'accept') === 'true' },
    });
    return redirect(safeReturn(result.returnTo));
  });
}
export default function Review() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  return (
    <Page title={t('reviewConnection')} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel title={t('before')}>
        <JsonView value={data.before} />
      </Panel>
      <Panel title={t('after')}>
        <JsonView value={data.after} />
      </Panel>
      <Form method="post">
        <div className="flex min-w-0 flex-wrap items-center gap-4">
          <Button type="submit" name="accept" value="true" variant="default">
            {t('accept')}
          </Button>
          <Button type="submit" name="accept" value="false" variant="ghost">
            {t('cancel')}
          </Button>
        </div>
      </Form>
    </Page>
  );
}
