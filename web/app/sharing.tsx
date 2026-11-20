import { Button } from './components/ui/button';
import { InputField, CheckboxField } from './form-fields';
import { useState } from 'react';
import { Form, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Action, Principal, Relation, Resource, RoleOf, listOf } from '../../shared/contracts';
import type { ActionName } from '../../shared/contracts';
import { actionResult, api, ApiFailure, formText, session } from './api';
import { requireKeys, resealNow } from './keys';
import { isProtected } from '../../shared/protected';
import { ErrorNotice, Page, Panel, SaveBar } from './components';
import { resourcePath } from './navigation';
// The actions a role gives, read back from its name: a reader may read, a user may use.
const actionOf = new Map<string, ActionName>(Object.entries(RoleOf).map(([action, role]) => [role, action as ActionName]));
// Who was given which actions here, one entry for each subject, from the lines drawn onto the target.
async function given(id: string, signal?: AbortSignal) {
  const lines = await api('/relations?' + new URLSearchParams({ object: id, limit: '200' }), { signal }, listOf(Relation));
  const bySubject = new Map<string, { principalId: string; principalName: string; actions: ActionName[] }>();
  for (const line of lines.items) {
    const action = actionOf.get(line.relation);
    if (!action) continue;
    const entry = bySubject.get(line.subjectId) ?? { principalId: line.subjectId, principalName: line.subjectName, actions: [] };
    entry.actions.push(action);
    bySubject.set(line.subjectId, entry);
  }
  return [...bySubject.values()];
}
export async function shareLoader({ params, request }: LoaderFunctionArgs) {
  const id = params.id ?? params.owner!;
  const [target, grants] = await Promise.all([
    params.id
      ? api('/resources/' + id, { signal: request.signal }, Resource)
      : api('/principals/' + id, { signal: request.signal }, Principal),
    given(id, request.signal),
  ]);
  const protectedItem = 'kind' in target && isProtected(target.kind);
  return { target, grants, protectedItem };
}
export async function shareAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const objectId = params.id ?? params.owner!;
    const id = formText(form, 'principalId');
    const remove = formText(form, 'intent') === 'remove';
    const actions = form.getAll('actions').map((value) => Action.parse(value));
    if (!remove && !actions.length) throw new ApiFailure('invalid_input');
    // Opening what a key protects means it is sealed for the one let in, which this browser does right after.
    const sealed = !!params.id && isProtected((await api('/resources/' + params.id, {}, Resource)).kind);
    const signedIn = (await session()).principal?.id;
    if (sealed && signedIn) await requireKeys(signedIn);
    // Each action is its own line: draw the ones now chosen, erase the ones no longer.
    const before = (await given(objectId)).find((entry) => entry.principalId === id)?.actions ?? [];
    const line = (action: ActionName) => ({ subjectId: id, relation: RoleOf[action], objectId });
    for (const action of actions.filter((action) => !before.includes(action)))
      await api('/relations', { method: 'POST', body: line(action) });
    for (const action of before.filter((action) => remove || !actions.includes(action)))
      await api('/relations', { method: 'DELETE', body: line(action) });
    if (sealed && signedIn) await resealNow(signedIn);
    return { ok: true };
  });
}
export default function Sharing() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof shareLoader>();
  const result = useActionData<typeof shareAction>();
  const [id, setId] = useState('');
  const [actions, setActions] = useState<ActionName[]>(['read']);
  const back =
    'kind' in data.target ? resourcePath(data.target) : '/p/' + data.target.id + '/settings/general';
  return (
    <Page title={t('share') + ' — ' + data.target.name} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel title={t('granted')}>
        <ul className="divide-y divide-border">
          {data.grants.map((grant) => (
            <li
              key={grant.principalId}
              className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0"
            >
              <div className="min-w-0 flex-1 space-y-1">
                <div className="font-medium wrap-anywhere">
                  {grant.principalName ?? grant.principalId}
                </div>
                <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                  {grant.actions.map((action) => t('permission.' + action)).join('、')}
                </div>
              </div>
              <Button
                onClick={() => {
                  setId(grant.principalId);
                  setActions(grant.actions);
                }}
                variant="ghost"
              >
                {t('edit')}
              </Button>
              <Form method="post">
                <input type="hidden" name="principalId" value={grant.principalId} />
                <Button type="submit" name="intent" value="remove" variant="destructive">
                  {t('removeAccess')}
                </Button>
              </Form>
            </li>
          ))}
        </ul>
        {!data.grants.length && <p className="leading-relaxed text-muted-foreground">{t('empty')}</p>}
      </Panel>
      <Form method="post">
        <div className="flex min-w-0 flex-col gap-6">
          <InputField
            name="principalId"
            label={t('recipient')}
            value={id}
            onChange={(event) => setId(event.target.value)}
            required
          />
          <Panel title={t('permissions')}>
            <div className="grid gap-3">
              {data.target.permissions
                .filter((action) => data.protectedItem ? ['read', 'reveal', 'update'].includes(action) : 'kind' in data.target || !['delete', 'transfer', 'use'].includes(action))
                .map((action) => (
                  <CheckboxField
                    name="actions"
                    value={action}
                    checked={actions.includes(action)}
                    key={action}
                    label={t('permission.' + action)}
                    onCheckedChange={(checked) =>
                      setActions(
                        checked === true
                          ? [...actions, action]
                          : actions.filter((value) => value !== action),
                      )
                    }
                  />
                ))}
            </div>
          </Panel>
          {data.protectedItem && actions.includes('update') && <p className="text-sm leading-relaxed text-muted-foreground">{t('editorDisclosure')}</p>}
          <SaveBar back={back} label="grant" />
        </div>
      </Form>
    </Page>
  );
}
