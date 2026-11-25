import { Link, redirect } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-complete';
import { Id, Resource } from '../../../shared/contracts';
import { OperationView } from '../../../shared/operations';
import { Notice, Page } from '../components';
import { connectionClient } from '../custody';
import { api, signedIn } from '../api';
import { resourcePath } from '../navigation';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const session = await signedIn(request);
  const parameters = new URL(request.url).searchParams;
  const id = Id.safeParse(parameters.get('flow')), operationId = Id.safeParse(parameters.get('operation'));
  if (id.success) {
    // A connection another device makes, such as a machine, is finished by that device: this browser only allowed it.
    if (operationId.success) {
      const operation = await api('/operations/' + operationId.data, {}, OperationView);
      if (operation.actor.id !== session.principal!.id) return { device: operation.actor.name, operationId: operation.id };
    }
    const progress = await (await connectionClient()).progress(id.data);
    // A connection a request asked for goes back to that request.
    const operation = await api('/operations/' + progress.flow.operationId, {}, OperationView);
    if (operation.requestId) return redirect('/requests/' + operation.requestId);
    if (progress.kind === 'connected') return redirect(resourcePath(await api('/resources/' + progress.id, {}, Resource)));
    return redirect('/operations/' + operation.id);
  }
  return null;
}
export default function ConnectionComplete({ loaderData }: Route.ComponentProps) {
  const { t } = useTranslation();
  return <Page title={t('connect')} narrow>
    <Notice tone="info">{loaderData ? t('connectionDeviceFinishes', { name: loaderData.device }) : t('connectionFlowHelp')}</Notice>
    {loaderData && <Link className="w-fit text-sm underline underline-offset-4" to={'/operations/' + loaderData.operationId}>{t('openOperation')}</Link>}
  </Page>;
}
