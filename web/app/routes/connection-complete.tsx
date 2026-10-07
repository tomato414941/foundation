import { redirect } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-complete';
import { Id } from '../../../shared/contracts';
import { Notice, Page } from '../components';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const id = Id.safeParse(new URL(request.url).searchParams.get('flow'));
  if (id.success) return redirect('/connections/' + id.data);
  return null;
}
export default function ConnectionComplete() {
  const { t } = useTranslation();
  return <Page title={t('connect')} narrow><Notice tone="info">{t('connectionFlowHelp')}</Notice></Page>;
}
