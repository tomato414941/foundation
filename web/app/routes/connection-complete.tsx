import { redirect } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-complete';
import { Id } from '../../../shared/contracts';
import { Notice, Page } from '../components';
import { connectionClient } from '../custody';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const id = Id.safeParse(new URL(request.url).searchParams.get('flow'));
  if (id.success) {
    const progress = await (await connectionClient()).progress(id.data);
    return redirect('/executions/' + progress.flow.execution.id);
  }
  return null;
}
export default function ConnectionComplete() {
  const { t } = useTranslation();
  return <Page title={t('connect')} narrow><Notice tone="info">{t('connectionFlowHelp')}</Notice></Page>;
}
