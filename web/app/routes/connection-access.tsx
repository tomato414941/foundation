import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-access';
import { Principal, Resource, listOf } from '../../../shared/contracts';
import { actionResult, api, ApiFailure, formText } from '../api';
import { custodyClient, operationClient } from '../custody';
import { requireKeys } from '../keys';
import { CheckboxField } from '../form-fields';
import { Detail, ErrorNotice, Page, Panel, SaveBar } from '../components';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.kind !== 'connection' || resource.ownerId !== params.owner || !resource.permissions.includes('update'))
    throw new Response('Not found', { status: 404 });
  const client = await custodyClient();
  const [principals, protectedItem, owner, owners] = await Promise.all([api('/principals?limit=200', {}, listOf(Principal)),
    client.read(resource.id), api('/principals/' + resource.ownerId, {}, Principal), client.ownerSide(resource.ownerId)]);
  // Those who use what the owner holds open the connection anyway; its users are the other principals it is sealed for.
  const users = protectedItem.content.policy.readers.map(reader => reader.principalId).filter(id => !owners.has(id));
  const missing = users.filter(id => !principals.items.some(principal => principal.id === id));
  const recipients = await Promise.all(missing.map(async id => {
    try { return await api('/principals/' + id, {}, Principal); }
    catch { return { id, name: id }; }
  }));
  return { resource, principals: [...principals.items, ...recipients].filter(principal => !owners.has(principal.id)), users, owner };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    await requireKeys();
    const made = await (await operationClient()).perform({ name: 'connection.authorize', input: { ownerId: params.owner!,
      connectionId: params.id!, version: Number(formText(form, 'version')), users: form.getAll('users').map(String) } });
    if (!('kind' in made) || made.kind !== 'saved') throw new ApiFailure('invalid_input');
    return redirect('/operations/' + made.operationId);
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
