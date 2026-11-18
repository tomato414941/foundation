import { redirect } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-complete';
import { Id, Resource } from '../../../shared/contracts';
import { OperationView } from '../../../shared/operations';
import { Notice, Page } from '../components';
import { connectionClient } from '../custody';
import { api, signedIn } from '../api';
import { resourcePath } from '../navigation';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const id = Id.safeParse(new URL(request.url).searchParams.get('flow'));
  if (id.success) {
    const progress = await (await connectionClient()).progress(id.data);
    // A connection a request asked for goes back to that request.
    const operation = await api('/operations/' + progress.flow.operationId, {}, OperationView);
    if (operation.request) return redirect('/requests/' + operation.request.id);
    if (progress.kind === 'connected') return redirect(resourcePath(await api('/resources/' + progress.id, {}, Resource)));
    return redirect('/operations/' + operation.id);
  }
  return null;
}
export default function ConnectionComplete() {
  const { t } = useTranslation();
  return <Page title={t('connect')} narrow><Notice tone="info">{t('connectionFlowHelp')}</Notice></Page>;
}
