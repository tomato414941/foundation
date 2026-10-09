import { Button } from '../components/ui/button';
import { SelectItem } from '../components/ui/select';
import { InputField, SelectField } from '../form-fields';
import { Form, Link, useActionData, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/principals';
import { Principal, Relation, listOf } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { Copy, ErrorNotice, Page, Paging, Panel } from '../components';
import { useWorkspace } from './workspace';
import { rekeySharing } from '../keys';

// The lines between principals that make up how they stand to one another; a single permission given on its own is
// managed where the principal is shared.
const relationships = ['agent', 'member', 'payer'];
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const search = new URL(request.url).searchParams;
  const page = (side: 'object' | 'subject', after: string | null) =>
    api(
      '/relations?' + new URLSearchParams({ [side]: params.owner, ...(after ? { after } : {}) }),
      { signal: request.signal },
      listOf(Relation),
    );
  const [onto, from, principals] = await Promise.all([
    page('object', search.get('after')),
    page('subject', search.get('fromAfter')),
    api('/principals', { signal: request.signal }, listOf(Principal)),
  ]);
  return {
    onto: { ...onto, items: onto.items.filter((line) => relationships.includes(line.relation)) },
    from: { ...from, items: from.items.filter((line) => relationships.includes(line.relation)) },
    owned: principals.items.filter((item) => item.owner?.id === params.owner),
  };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const subjectId = formText(form, 'subjectId'),
      relation = formText(form, 'relation'),
      objectId = formText(form, 'objectId') || params.owner;
    const remove = formText(form, 'intent') === 'remove';
    const contents =
      relation === 'member'
        ? await rekeySharing('/relations/recipients?' + new URLSearchParams({ subjectId, objectId, remove: String(remove) }))
        : undefined;
    await api('/relations', {
      method: remove ? 'DELETE' : 'POST',
      body: { subjectId, relation, objectId, ...(contents ? { contents } : {}) },
    });
    return { ok: true };
  });
}
export default function Principals() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { principal } = useWorkspace();
  const [search] = useSearchParams();
  const line = (subject: string, relation: string, object: string) =>
    t('line', { subject, relation: t(relation), object });
  const item = (key: string, id: string, name: string, text: string, remove?: { subjectId: string; relation: string; objectId: string }) => (
    <li key={key} className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="font-medium wrap-anywhere">
          <Link to={'/p/' + id}>{name}</Link>
        </div>
        <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">{text}</div>
      </div>
      <Copy value={id} />
      {remove && principal.permissions.includes('share') && (
        <Form method="post">
          <input type="hidden" name="subjectId" value={remove.subjectId} />
          <input type="hidden" name="objectId" value={remove.objectId} />
          <input type="hidden" name="relation" value={remove.relation} />
          <Button type="submit" name="intent" value="remove" variant="destructive">
            {t('removeAccess')}
          </Button>
        </Form>
      )}
    </li>
  );
  const empty = !principal.owner && !data.owned.length && !data.onto.items.length && !data.from.items.length;
  return (
    <Page
      title={t('principals')}
      actions={
        principal.permissions.includes('create') && (
          <Button variant="default" asChild>
            <Link to="new">{t('createPrincipal')}</Link>
          </Button>
        )
      }
    >
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel title={t('connectedPrincipals')}>
        <ul className="divide-y divide-border">
          {principal.owner &&
            item('owner', principal.owner.id, principal.owner.name, line(principal.owner.name, 'owner', principal.name))}
          {data.owned.map((owned) => item('owns:' + owned.id, owned.id, owned.name, line(principal.name, 'owner', owned.name)))}
          {data.onto.items.map((entry) =>
            item('onto:' + entry.subjectId + entry.relation, entry.subjectId, entry.subjectName,
              line(entry.subjectName, entry.relation, principal.name), entry),
          )}
          {data.from.items.map((entry) =>
            item('from:' + entry.objectId + entry.relation, entry.objectId, entry.objectName,
              line(principal.name, entry.relation, entry.objectName), entry),
          )}
        </ul>
        {empty && <p className="leading-relaxed text-muted-foreground">{t('empty')}</p>}
        <Paging next={data.onto.next} search={search} />
        <Paging next={data.from.next} search={search} param="fromAfter" />
      </Panel>
      {principal.permissions.includes('share') && (
        <Panel title={t('add')}>
          <Form method="post">
            <div className="flex min-w-0 flex-col gap-6">
              <InputField name="subjectId" label={t('subject')} required />
              <SelectField name="relation" label={t('relation')} defaultValue="agent">
                {relationships.map((value) => (
                  <SelectItem key={value} value={value}>
                    {t(value)}
                  </SelectItem>
                ))}
              </SelectField>
              <p className="leading-relaxed text-muted-foreground text-sm">{t('relationHelp')}</p>
              <p className="leading-relaxed text-muted-foreground text-sm">{t('paymentHelp')}</p>
              <Button type="submit" variant="default">
                {t('add')}
              </Button>
            </div>
          </Form>
        </Panel>
      )}
    </Page>
  );
}
