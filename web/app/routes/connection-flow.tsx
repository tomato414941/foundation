import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-flow';
import { Resource } from '../../../shared/contracts';
import { api, actionResult, formText, signedIn } from '../api';
import { connectionClient } from '../custody';
import { ErrorNotice, Notice, Page, usePolling } from '../components';
import { resourcePath } from '../navigation';
import { ConnectionProgress } from '../connection-progress';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return actionResult(async () => {
    const progress = await (await connectionClient()).progress(params.id);
    if (progress.kind === 'connected') return redirect(progress.flow.approval
      ? '/executions/' + progress.flow.execution.id : resourcePath(await api('/resources/' + progress.id, {}, Resource)));
    return progress;
  });
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), client = await connectionClient();
    if (formText(form, 'intent') === 'cancel') await client.cancel(params.id);
    else await client.accept(params.id);
    return { ok: true };
  });
}
export default function ConnectionFlow() {
  const { t } = useTranslation(), data = useLoaderData<typeof clientLoader>(), result = useActionData<typeof clientAction>();
  const progress = 'kind' in data ? data : null;
  usePolling(progress?.kind === 'pending' || progress?.kind === 'authorize');
  return <Page title={progress?.flow.name ?? t('connect')} narrow>
    <ErrorNotice error={'error' in data && typeof data.error === 'string' ? data.error : result && 'error' in result ? result.error : null} />
    {!progress && <Notice tone="info">{t('connectionFlowHelp')}</Notice>}
    {progress && <Form method="post"><ConnectionProgress progress={progress} /></Form>}
    <Link className="text-sm underline underline-offset-4" to="/account">{t('account')}</Link>
  </Page>;
}
