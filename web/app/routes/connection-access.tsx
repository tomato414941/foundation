import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-access';
import { Principal, Resource, listOf } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { custodyClient, executionClient } from '../custody';
import { CheckboxField } from '../form-fields';
import { Detail, ErrorNotice, Page, Panel, SaveBar } from '../components';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.kind !== 'connection' || resource.ownerId !== params.owner || !resource.permissions.includes('update'))
    throw new Response('Not found', { status: 404 });
  const [principals, protectedItem, owner] = await Promise.all([api('/principals?limit=200', {}, listOf(Principal)),
    (await custodyClient()).read(resource.id), api('/principals/' + resource.ownerId, {}, Principal)]);
  const users = protectedItem.content.policy.grants.flatMap(grant => 'actor' in grant ? [grant.actor.principalId] : []);
  const missing = users.filter(id => !principals.items.some(principal => principal.id === id));
  const recipients = await Promise.all(missing.map(async id => {
    try { return await api('/principals/' + id, {}, Principal); }
    catch { return { id, name: id }; }
  }));
  return { resource, principals: [...principals.items, ...recipients], users, owner };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), client = await executionClient();
    const execution = await client.start({ name: 'connection.authorize', input: { ownerId: params.owner!,
      connectionId: params.id!, version: Number(formText(form, 'version')), users: form.getAll('users').map(String) } });
    await client.continue(execution.id);
    return redirect('/executions/' + execution.id);
  });
}
export default function ConnectionAccess() {
  const { t } = useTranslation(), { resource, principals, users, owner } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  return <Page title={t('authorizeConnection')} narrow>
    <ErrorNotice error={result && 'error' in result ? result.error : null} />
    <Form method="post" className="space-y-6">
      <input type="hidden" name="version" value={resource.version} />
      <Panel title={resource.name}>
        <Detail label={t('owner')}><Link className="underline underline-offset-4" to={'/p/' + owner.id}>{owner.name}</Link></Detail>
        <p className="text-sm text-muted-foreground">{t('connectionPermissionHelp')}</p>
        {principals.map(principal => <CheckboxField key={principal.id} name="users" value={principal.id}
          label={principal.name} defaultChecked={users.includes(principal.id)} />)}
        <Link className="text-sm underline underline-offset-4" to="/account/trust">{t('trustIdentity')}</Link>
      </Panel>
      <SaveBar back={'/p/' + resource.ownerId + '/services/' + resource.id} />
    </Form>
  </Page>;
}
