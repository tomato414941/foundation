import { Button } from '../components/ui/button';
import { SelectItem } from '../components/ui/select';
import { InputField, SelectField } from '../form-fields';
import { Form, Link, useActionData, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/principals';
import { Relation, listOf } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { Copy, ErrorNotice, Page, Paging, Panel } from '../components';
import { useWorkspace } from './workspace';
import { rekeySharing } from '../keys';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  return api(
    `/principals/${params.owner}/relations?${new URL(request.url).searchParams}`,
    { signal: request.signal },
    listOf(Relation),
  );
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const subjectId = formText(form, 'subjectId'),
      relation = formText(form, 'relation'),
      principalId = formText(form, 'principalId') || params.owner;
    const remove = formText(form, 'intent') === 'remove';
    const secrets =
      relation === 'member'
        ? await rekeySharing('/relations/recipients?' + new URLSearchParams({ subjectId, principalId, remove: String(remove) }))
        : undefined;
    await api('/relations', {
      method: remove ? 'DELETE' : 'POST',
      body: { subjectId, relation, principalId, ...(secrets ? { secrets } : {}) },
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
          {data.items.map((item) => {
            const incoming = item.principalId === principal.id;
            const id = incoming ? item.subjectId : item.principalId;
            return (
              <li key={item.id} className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0">
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="font-medium wrap-anywhere">
                    {<Link to={'/p/' + id}>{incoming ? item.subjectName : item.principalName}</Link>}
                  </div>
                  <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">{`${item.subjectName} → ${t(item.relation)} → ${item.principalName}`}</div>
                </div>
                <Copy value={id} />
                {principal.permissions.includes('share') && item.relation !== 'owner' && (
                  <Form method="post">
                    <input type="hidden" name="subjectId" value={item.subjectId} />
                    <input type="hidden" name="principalId" value={item.principalId} />
                    <input type="hidden" name="relation" value={item.relation} />
                    <Button type="submit" name="intent" value="remove" variant="destructive">
                      {t('removeAccess')}
                    </Button>
                  </Form>
                )}
              </li>
            );
          })}
        </ul>
        {!data.items.length && <p className="leading-relaxed text-muted-foreground">{t('empty')}</p>}
        <Paging next={data.next} search={search} />
      </Panel>
      {principal.permissions.includes('share') && (
        <Panel title={t('add')}>
          <Form method="post">
            <div className="flex min-w-0 flex-col gap-6">
              <InputField name="subjectId" label={t('subject')} required />
              <SelectField name="relation" label={t('relation')} defaultValue="agent">
                {['agent', 'member', 'payer'].map((value) => (
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
