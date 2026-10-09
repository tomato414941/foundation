import { Button } from './components/ui/button';
import { InputField, CheckboxField } from './form-fields';
import { useState } from 'react';
import { Form, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Action, Principal, Relation, Resource, RoleOf, listOf } from '../../shared/contracts';
import type { ActionName } from '../../shared/contracts';
import { actionResult, api, ApiFailure, formText } from './api';
import { custodyClient } from './custody';
import { hash } from '../../shared/authority';
import { Operations, permittedOperations } from '../../shared/custody';
import { isProtected } from '../../shared/protected';
import { availableEnvironments, EnvironmentChoice } from './environments';
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
  return { target, grants, protectedItem,
    environments: protectedItem ? await availableEnvironments(target.ownerId) : [] };
}
export async function shareAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const objectId = params.id ?? params.owner!;
    const id = formText(form, 'principalId');
    const remove = formText(form, 'intent') === 'remove';
    const actions = form.getAll('actions').map((value) => Action.parse(value));
    if (!remove && !actions.length) throw new ApiFailure('invalid_input');
    if (params.id) {
      const resource = await api('/resources/' + params.id, {}, Resource);
      if (isProtected(resource.kind)) {
        const client = await custodyClient(), previous = await client.read(resource.id);
        const policy = { ...previous.content.policy, revision: previous.content.policy.revision + 1, producers: [],
          readers: previous.content.policy.readers.filter(reader => reader.principalId !== id),
          authorities: previous.content.policy.authorities.filter(authority => authority.principalId !== id),
          grants: previous.content.policy.grants.filter(grant => grant.actor.principalId !== id && (remove ? grant.executor.principalId !== id : true)),
          observers: (previous.content.policy.observers ?? []).filter(observer => observer !== id) };
        if (!remove) {
          if (actions.includes('read')) policy.observers.push(id);
          if (actions.some(action => ['reveal', 'update', 'use'].includes(action))) {
            const { binding } = await client.inspectIdentity(id); await client.trusted(binding);
            if (actions.includes('reveal') || actions.includes('update')) policy.readers.push(binding);
            if (actions.includes('update')) policy.authorities.push(binding);
            if (actions.includes('use')) {
              const environments = await Promise.all(form.getAll('environments').map(id => client.environment(String(id))));
              if (!environments.length) throw new ApiFailure('environment_required');
              const functionId = formText(form, 'functionId'), callerProgram = form.has('callerProgram');
              const fn = functionId ? await api('/resources/' + functionId, {}, Resource) : null;
              if (resource.kind !== 'app' && !callerProgram && (!fn || fn.kind !== 'function')) throw new ApiFailure('function_required');
              for (const environment of environments) {
                policy.grants.push({ actor: binding, executor: environment.manifest.executor,
                  operations: callerProgram || resource.kind === 'app' ? [...permittedOperations(policy.contentType)] : [Operations.function],
                  callerProgram, origins: [], functionDigests: fn?.kind === 'function' ? [await hash(fn.data)] : [],
                  expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() });
              }
            }
          }
        }
        await client.save(resource.name, await client.reveal(resource.id), policy, { previous, metadata: previous.content.metadata });
        return { ok: true };
      }
    }
    // Each action is its own line: draw the ones now chosen, erase the ones no longer.
    const before = (await given(objectId)).find((entry) => entry.principalId === id)?.actions ?? [];
    const line = (action: ActionName) => ({ subjectId: id, relation: RoleOf[action], objectId });
    for (const action of actions.filter((action) => !before.includes(action)))
      await api('/relations', { method: 'POST', body: line(action) });
    for (const action of before.filter((action) => remove || !actions.includes(action)))
      await api('/relations', { method: 'DELETE', body: line(action) });
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
                .filter((action) => data.protectedItem ? ['read', 'reveal', 'update', 'use'].includes(action) : 'kind' in data.target || !['delete', 'transfer', 'use'].includes(action))
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
          {data.protectedItem && actions.includes('use') && <>
            <EnvironmentChoice items={data.environments} multiple />
            <InputField name="functionId" label={t('approvedFunction')} />
            <CheckboxField name="callerProgram" label={t('callerProgram')} hint={t('callerProgramHelp')} />
          </>}
          <SaveBar back={back} label="grant" />
        </div>
      </Form>
    </Page>
  );
}
