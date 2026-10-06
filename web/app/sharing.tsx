import { Button } from './components/ui/button';
import { InputField, CheckboxField } from './form-fields';
import { useState } from 'react';
import { Form, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Action, Grant, Principal, Resource, listOf } from '../../shared/contracts';
import type { ActionName } from '../../shared/contracts';
import { actionResult, api, ApiFailure, formText, session } from './api';
import { decryptSecret, sealSecret } from './keys';
import { ErrorNotice, Page, Panel, SaveBar } from './components';
import { resourcePath } from './navigation';
export async function shareLoader({ params, request }: LoaderFunctionArgs) {
  const prefix = params.id ? '/resources/' + params.id : '/principals/' + params.owner;
  const [target, grants] = await Promise.all([
    params.id
      ? api(prefix, { signal: request.signal }, Resource)
      : api(prefix, { signal: request.signal }, Principal),
    api(prefix + '/grants', { signal: request.signal }, listOf(Grant)),
  ]);
  return { target, grants: grants.items, prefix };
}
export async function shareAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const prefix = params.id ? '/resources/' + params.id : '/principals/' + params.owner;
    const id = formText(form, 'principalId');
    const remove = formText(form, 'intent') === 'remove';
    const actions = form.getAll('actions').map((value) => Action.parse(value));
    if (!remove && !actions.length) throw new ApiFailure('invalid_input');
    if (params.id && actions.includes('reveal')) {
      const resource = await api('/resources/' + params.id, {}, Resource);
      if (resource.kind === 'secret' && !resource.data.recipients.includes(id)) {
        const data = await session();
        const content = await decryptSecret(resource.id, data.principal!.id);
        const sealed = await sealSecret(
          resource.id,
          resource.ownerId,
          content,
          data.server,
          resource.data.allowUse,
          [...resource.data.recipients, id],
          true,
        );
        await api('/resources/' + resource.id, {
          method: 'PATCH',
          body: { version: resource.version, sealed, bytes: content.length },
        });
      }
    }
    await api(prefix + '/grants/' + id, {
      method: remove ? 'DELETE' : 'PUT',
      ...(remove ? {} : { body: { actions } }),
    });
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
                .filter((action) => 'kind' in data.target || !['delete', 'transfer'].includes(action))
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
          <SaveBar back={back} label="grant" />
        </div>
      </Form>
    </Page>
  );
}
