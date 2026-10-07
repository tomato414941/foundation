import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-flow';
import { Resource } from '../../../shared/contracts';
import { api, actionResult, formText, signedIn } from '../api';
import { connectionClient } from '../custody';
import { Button } from '../components/ui/button';
import { Detail, ErrorNotice, ExternalLink, Notice, Page, Panel, State, usePolling } from '../components';
import { resourcePath } from '../navigation';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return actionResult(async () => {
    const progress = await (await connectionClient()).progress(params.id);
    if (progress.kind === 'connected') return redirect(progress.flow.approval
      ? '/requests/' + progress.flow.approval.id : resourcePath(await api('/resources/' + progress.id, {}, Resource)));
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
    {progress?.kind === 'pending' && <Notice tone="info">{t('connectionPending')}</Notice>}
    {progress?.kind === 'authorize' && <Panel>
      <ExternalLink href={progress.url}>{t('authorizeService')}</ExternalLink>
    </Panel>}
    {progress?.kind === 'review' && <Panel title={t('connectionApprove')}>
      <Detail label={t('accountName')}>{String(progress.metadata.account ?? t('accountUnverified'))}</Detail>
      {!progress.metadata.accountVerified && <Notice tone="warning">{t('accountUnverified')}</Notice>}
      <Detail label={t('scopes')}>{Array.isArray(progress.metadata.scopes) && progress.metadata.scopes.length
        ? progress.metadata.scopes.join(', ') : t('scopesUnknown')}</Detail>
      <Form method="post"><Button type="submit">{t('save')}</Button></Form>
    </Panel>}
    {progress?.kind === 'failed' && <Panel><State value={progress.task.state} />
      <ErrorNotice error={progress.error && typeof progress.error === 'object' && !Array.isArray(progress.error) && typeof progress.error.code === 'string' ? progress.error.code : 'failure'} />
    </Panel>}
    {progress?.kind === 'cancelled' && <State value="cancelled" />}
    {progress && !['cancelled', 'connected', 'failed'].includes(progress.kind) && <Form method="post">
      <Button variant="ghost" type="submit" name="intent" value="cancel">{t('cancel')}</Button>
    </Form>}
    <Link className="text-sm underline underline-offset-4" to="/account">{t('account')}</Link>
  </Page>;
}
