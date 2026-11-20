import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/connection-access';
import { Principal, Recipient, Relation, Resource, listOf } from '../../../shared/contracts';
import { actionResult, api, ApiFailure, formText, session } from '../api';
import { operationClient } from '../custody';
import { requireKeys, resealNow } from '../keys';
import { CheckboxField } from '../form-fields';
import { Detail, ErrorNotice, Page, Panel, SaveBar } from '../components';

export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.kind !== 'connection' || resource.ownerId !== params.owner || !resource.permissions.includes('share'))
    throw new Response('Not found', { status: 404 });
  const [principals, lines, owner, recipients] = await Promise.all([api('/principals?limit=200', {}, listOf(Principal)),
    api('/relations?' + new URLSearchParams({ object: resource.id, limit: '200' }), {}, listOf(Relation)),
    api('/principals/' + resource.ownerId, {}, Principal), api('/principals/' + resource.ownerId + '/recipients', {}, listOf(Recipient))]);
  // Those who use what the owner holds open the connection anyway; its users are those it is shared with to open it.
  const owners = new Set([resource.ownerId, ...recipients.items.map(recipient => recipient.id)]);
  const users = lines.items.filter(line => line.relation === 'revealer').map(line => line.subjectId);
  const missing = users.filter(id => !principals.items.some(principal => principal.id === id));
  const others = await Promise.all(missing.map(async id => {
    try { return await api('/principals/' + id, {}, Principal); }
    catch { return { id, name: id }; }
  }));
  return { resource, principals: [...principals.items, ...others].filter(principal => !owners.has(principal.id)), users, owner };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), signedIn = (await session()).principal?.id;
    if (!signedIn) throw new ApiFailure('unauthenticated');
    // The users chosen are let in at once; this browser seals the connection for them right after.
    await requireKeys(signedIn);
    const made = await (await operationClient()).perform({ name: 'connection.authorize', input: { ownerId: params.owner!,
      connectionId: params.id!, version: Number(formText(form, 'version')), users: form.getAll('users').map(String) } });
    if (!('id' in made) || !('state' in made)) throw new ApiFailure('invalid_input');
    await resealNow(signedIn);
    return redirect('/operations/' + made.id);
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
      </Panel>
      <SaveBar back={'/p/' + resource.ownerId + '/services/' + resource.id} />
    </Form>
  </Page>;
}
