import { Button } from './components/ui/button';
import { SelectItem } from './components/ui/select';
import { InputField, CheckboxField, SelectField } from './form-fields';
import { PrincipalField } from './principal-field';
import { useEffect, useState } from 'react';
import { Form, useActionData, useFetcher, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Action, Ok, Principal, Relation, Resource, RoleOf, listOf } from '../../shared/contracts';
import type { ActionName, ConnectionView } from '../../shared/contracts';
import { ConnectionSharePermission } from '../../shared/connection-sharing';
import { KeySharingItem } from '../../shared/protocol';
import { actionResult, api, ApiFailure, formText, session } from './api';
import { custodyClient } from './custody';
import { requireKeys, resealNow } from './keys';
import { isProtected } from '../../shared/protected';
import { ErrorNotice, Notice, Page, Panel, SaveBar } from './components';
import { resourcePath } from './navigation';
import { useWorkspace } from './routes/workspace';

type Grant = { principalId: string; principalName: string; actions: ActionName[] };
// The actions a role gives, read back from its name: a reader may read, a user may use.
const actionOf = new Map<string, ActionName>(Object.entries(RoleOf).map(([action, role]) => [role, action as ActionName]));
// Who was given which actions here, one entry for each subject, from the lines drawn onto the target.
async function given(id: string, signal?: AbortSignal) {
  const lines = await api('/relations?' + new URLSearchParams({ object: id, limit: '200' }), { signal }, listOf(Relation));
  const bySubject = new Map<string, Grant>();
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
    const item = params.id ? await api('/resources/' + params.id, {}, Resource) : null;
    if (item?.kind === 'connection') {
      const permission = remove ? null : ConnectionSharePermission.parse(formText(form, 'actions'));
      const path = '/connections/' + item.id + '/shares/' + encodeURIComponent(id);
      const plan = permission === 'reveal' || permission === 'update'
        ? await api(path + '/recipients?permission=' + permission, {}, KeySharingItem.nullable()) : null;
      let protection;
      if (plan) {
        await requireKeys();
        protection = (await (await custodyClient()).sharing([plan]))[item.id];
      }
      await api(path, { method: 'PUT', body: { permission, protection } }, Ok);
      return { ok: true, removed: remove };
    }
    const actions = remove ? [] : form.getAll('actions').map((value) => Action.parse(value));
    if (!remove && !actions.length) throw new ApiFailure('invalid_input');
    // Opening what a key protects means it is sealed for the one let in, which this browser does right after.
    const sealed = item && isProtected(item.kind);
    const signedIn = (await session()).principal?.id;
    if (sealed && signedIn) await requireKeys(signedIn);
    // Each action is its own line: draw the ones now chosen, erase the ones no longer.
    const before = (await given(objectId)).find((entry) => entry.principalId === id)?.actions ?? [];
    const line = (action: ActionName) => ({ subjectId: id, relation: RoleOf[action], objectId });
    try {
      for (const action of actions.filter((action) => !before.includes(action)))
        await api('/relations', { method: 'POST', body: line(action) });
      for (const action of before.filter((action) => !actions.includes(action)))
        await api('/relations', { method: 'DELETE', body: line(action) });
    } finally {
      if (sealed && signedIn) await resealNow(signedIn);
    }
    return { ok: true, removed: remove };
  });
}
export default function Sharing() {
  const { target, grants } = useLoaderData<typeof shareLoader>();
  return 'kind' in target && target.kind === 'connection'
    ? <ConnectionSharing key={target.id} item={target} grants={grants} />
    : <ResourceSharing />;
}

const connectionPermissions = [
  { action: 'read', label: 'permission.read' },
  { action: 'reveal', label: 'connectionShareUse' },
  { action: 'update', label: 'connectionShareEdit' },
] as const;
type ConnectionPermission = (typeof connectionPermissions)[number]['action'];

function ConnectionSharing({ item, grants }: { item: ConnectionView; grants: Grant[] }) {
  const { t } = useTranslation();
  const { session } = useWorkspace();
  const fetcher = useFetcher<typeof shareAction>();
  const [editor, setEditor] = useState<Grant | 'new' | null>(null);
  const [permission, setPermission] = useState<ConnectionPermission>('read');
  const busy = fetcher.state !== 'idle';
  const result = fetcher.data;
  const saved = !busy && result && 'ok' in result;
  const error = !busy && result && 'error' in result ? result.error : null;
  const permissions = connectionPermissions.filter(entry => item.permissions.includes(entry.action));
  const strongest = (grant: Grant) => connectionPermissions.findLast(entry => grant.actions.includes(entry.action));
  const principals = session.principals.filter(principal => principal.id !== item.ownerId &&
    !grants.some(grant => grant.principalId === principal.id));
  const existing = editor && editor !== 'new' ? editor : null;

  useEffect(() => {
    if (saved) setEditor(null);
  }, [saved]);

  function edit(grant: Grant | 'new') {
    fetcher.reset();
    setEditor(grant);
    setPermission(grant === 'new' ? 'read' : strongest(grant)?.action ?? 'read');
  }

  const editorForm = editor && <fetcher.Form key={existing?.principalId ?? 'new'} method="post" className="grid gap-4 py-4">
    {existing ? <div className="font-medium wrap-anywhere">
      {existing.principalName}
      <input type="hidden" name="principalId" value={existing.principalId} />
    </div> : <PrincipalField name="principalId" label={t('shareRecipient')} idLabel={t('recipient')} principals={principals} />}
    <SelectField name="actions" label={t('permissions')} value={permission}
      onValueChange={value => setPermission(value as ConnectionPermission)}
      hint={permission === 'read' ? undefined : t('connectionShareCredentialHelp')}>
      {permissions.map(entry => <SelectItem key={entry.action} value={entry.action}>{t(entry.label)}</SelectItem>)}
    </SelectField>
    <div className="flex flex-wrap items-center gap-2">
      <Button type="submit" loading={busy}>{t(existing ? 'save' : 'share')}</Button>
      <Button variant="ghost" disabled={busy} onClick={() => { fetcher.reset(); setEditor(null); }}>{t('cancel')}</Button>
      {existing && <Button type="submit" name="intent" value="remove" variant="ghost" disabled={busy}
        className="text-destructive hover:text-destructive">{t('removeShare')}</Button>}
    </div>
  </fetcher.Form>;

  return <Page title={t('share')} narrow back={{ to: resourcePath(item), label: item.name }}
    actions={<Button variant="outline" disabled={busy} onClick={() => edit('new')}>{t('addShareRecipient')}</Button>}>
    {error && <Notice tone="error">{error === 'network' ? t('connectionShareUnconfirmed') : <>
      <span className="block font-medium">{t('connectionShareFailed')}</span>
      {error === 'connection_busy' ? t('connectionShareBusy') : t('errors.' + error, { defaultValue: t('failure') })}
    </>}</Notice>}
    {saved && <p role="status" className="text-sm">{t(result.removed ? 'connectionShareRemoved' : 'connectionShareSaved')}</p>}
    {editor === 'new' && <div className="border-y">{editorForm}</div>}
    {grants.length ? <ul className="divide-y border-y" aria-label={t('shareRecipient')}>
      {grants.map(grant => {
        const entry = strongest(grant);
        return <li key={grant.principalId}>
          {existing?.principalId === grant.principalId ? editorForm : <div className="flex items-center justify-between gap-3 py-3">
            <div className="min-w-0 space-y-1 wrap-anywhere">
              <p className="font-medium">{grant.principalName}</p>
              {entry && <p className="text-sm text-muted-foreground">{t(entry.label)}</p>}
            </div>
            <Button variant="ghost" disabled={busy} onClick={() => edit(grant)}>{t('edit')}</Button>
          </div>}
        </li>;
      })}
    </ul> : !editor && <p className="text-sm text-muted-foreground">{t('emptyShareRecipients')}</p>}
  </Page>;
}

function ResourceSharing() {
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
