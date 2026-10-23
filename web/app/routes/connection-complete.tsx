import { redirect } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-complete';
import { Id, Resource } from '../../../shared/contracts';
import { Execution } from '../../../shared/executions';
import { Notice, Page } from '../components';
import { connectionClient } from '../custody';
import { api, signedIn } from '../api';
import { resourcePath } from '../navigation';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const id = Id.safeParse(new URL(request.url).searchParams.get('flow'));
  if (id.success) {
    const progress = await (await connectionClient()).progress(id.data);
    const execution = await api('/executions/' + progress.flow.execution.id, {}, Execution);
    if (execution.requests.length) return redirect('/requests/' + execution.requests.at(-1));
    if (progress.kind === 'connected') return redirect(resourcePath(await api('/resources/' + progress.id, {}, Resource)));
    return redirect('/executions/' + progress.flow.execution.id);
  }
  return null;
}
export default function ConnectionComplete() {
  const { t } = useTranslation();
  return <Page title={t('connect')} narrow><Notice tone="info">{t('connectionFlowHelp')}</Notice></Page>;
}
