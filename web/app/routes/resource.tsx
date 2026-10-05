import { useState } from 'react';
import { Link, redirect, useActionData, useLoaderData } from 'react-router';
import { Alert, Button, Checkbox, FormControlLabel, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource';
import { Resource } from '../../../shared/contracts';
import { decode } from '../../../shared/encryption';
import { api, actionResult, formText } from '../api';
import { authenticate, decryptSecret } from '../keys';
import {
  Bytes,
  Confirm,
  Copy,
  DateText,
  Detail,
  ErrorNotice,
  JsonView,
  Page,
  Panel,
  State,
  usePolling,
  useTask,
} from '../components';
import { resourceKind } from '../navigation';
import { useWorkspace } from './workspace';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.ownerId !== params.owner || resource.kind !== resourceKind(params.section))
    throw new Response('Not found', { status: 404 });
  return resource;
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    if (formText(form, 'intent') === 'stop') {
      await api(`/resources/${params.id}/stop`, { method: 'POST', body: {} });
      return { ok: true };
    }
    await api(`/resources/${params.id}?revoke=${form.has('revoke')}`, { method: 'DELETE' });
    return redirect(`/p/${params.owner}/${params.section}`);
  });
}
function downloadBytes(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)]));
  const element = document.createElement('a');
  element.href = url;
  element.download = name;
  element.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export default function ResourceDetail() {
  const item = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const { t } = useTranslation();
  const task = useTask();
  const [content, setContent] = useState<Uint8Array | null>(null);
  const [link, setLink] = useState<{ url: string; expiresAt: string } | null>(null);
  const [minutes, setMinutes] = useState(15);
  const can = (action: (typeof item.permissions)[number]) => item.permissions.includes(action);
  usePolling(
    item.kind === 'environment' && ['starting', 'running', 'stopping'].includes(item.data.state),
    item.kind === 'environment' && item.data.state === 'running' ? 15000 : 2500,
  );
  const secret = async () => {
    try {
      return await decryptSecret(item.id, session.principal!.id);
    } catch {
      const result = await authenticate(session.principal!.id);
      if (!result.encrypted) throw new Error('key unavailable');
      return decryptSecret(item.id, session.principal!.id);
    }
  };
  return (
    <Page
      title={item.name}
      actions={
        <>
          {can('update') && !['environment', 'connection'].includes(item.kind) && (
            <Button component={Link} to="edit" variant="outlined">
              {t('edit')}
            </Button>
          )}
          {can('share') && (
            <Button component={Link} to="share">
              {t('share')}
            </Button>
          )}
          {can('transfer') && item.kind !== 'environment' && (
            <Button component={Link} to="transfer">
              {t('transfer')}
            </Button>
          )}
        </>
      }
    >
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <Panel>
        <BoxDetails item={item} />
      </Panel>
      {item.kind === 'secret' && can('reveal') && (
        <Panel>
          <Stack direction="row" spacing={1}>
            <Button
              variant="contained"
              loading={task.busy}
              onClick={() => task.run(async () => setContent(content ? null : await secret()))}
            >
              {t(content ? 'hide' : 'reveal')}
            </Button>
            <Button
              loading={task.busy}
              onClick={() => task.run(async () => downloadBytes(await secret(), item.name))}
            >
              {t('download')}
            </Button>
          </Stack>
          {content && (
            <>
              <TextField
                label={t('value')}
                value={decode(content)}
                multiline
                minRows={3}
                fullWidth
                slotProps={{ input: { readOnly: true }, htmlInput: { spellCheck: false } }}
              />
              <Copy value={decode(content)} />
            </>
          )}
        </Panel>
      )}
      {item.kind === 'connection' && (
        <Panel title={t('outputs')}>
          {item.data.state !== 'ready' && <Alert severity="warning">{t('state.' + item.data.state)}</Alert>}
          <JsonView value={item.data.outputs} />
          {can('update') && (
            <Button component={Link} to={`../new?connection=${item.id}`} relative="path" variant="outlined">
              {t('reconnect')}
            </Button>
          )}
        </Panel>
      )}
      {item.kind === 'object' && (
        <Panel>
          <Stack direction="row" spacing={2}>
            <Button href={`/api/resources/${item.id}/content`} variant="contained">
              {t('download')}
            </Button>
            {can('update') && (
              <Button component={Link} to="edit">
                {t('replaceFile')}
              </Button>
            )}
          </Stack>
          <Typography variant="body2" color="text.secondary">
            {t('linkHelp')}
          </Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              size="small"
              type="number"
              label={t('expires') + ' (' + t('minutes') + ')'}
              value={minutes}
              onChange={(event) => setMinutes(Number(event.target.value))}
              slotProps={{ htmlInput: { min: 1, max: 1440 } }}
            />
            <Button
              loading={task.busy}
              onClick={() =>
                task.run(async () =>
                  setLink(await api(`/resources/${item.id}/link`, { method: 'POST', body: { minutes } })),
                )
              }
            >
              {t('createLink')}
            </Button>
          </Stack>
          {link && (
            <>
              <TextField label={t('link')} value={link.url} slotProps={{ input: { readOnly: true } }} />
              <Copy value={link.url} />
              <Typography variant="body2">
                <DateText value={link.expiresAt} />
              </Typography>
            </>
          )}
        </Panel>
      )}
      {item.kind === 'environment' && (
        <Panel>
          <Detail label={t('image')}>{item.data.image ?? t('defaultImage')}</Detail>
          <Detail label={t('size')}>{t(item.data.size)}</Detail>
          <Detail label={t('maximum')}>{item.data.lifetime.maxSeconds / 60}</Detail>
          <Detail label={t('idle')}>{item.data.lifetime.idleSeconds / 60}</Detail>
          {item.data.error && <Alert severity="error">{t('failure')}</Alert>}
          {item.data.state === 'running' && can('execute') && (
            <Button component={Link} to="run" variant="contained">
              {t('execute')}
            </Button>
          )}
          {['starting', 'running'].includes(item.data.state) && can('update') && (
            <Confirm label={t('stop')} name={item.name} body={t('stopBody')} danger={false}>
              <input type="hidden" name="intent" value="stop" />
            </Confirm>
          )}
          {['stopped', 'failed'].includes(item.data.state) && (
            <Typography color="text.secondary">{t('stoppedHelp')}</Typography>
          )}
        </Panel>
      )}
      {item.kind === 'function' && (
        <Panel>
          <Typography>{item.data.description}</Typography>
          <JsonView value={item.data} />
          {can('execute') && (
            <Button component={Link} to="run" variant="contained">
              {t('execute')}
            </Button>
          )}
        </Panel>
      )}
      {(item.kind === 'service' || item.kind === 'app') && (
        <Panel>
          <JsonView value={item.data} />
        </Panel>
      )}
      {can('delete') && (
        <Stack direction="row">
          <Confirm label={t(item.kind === 'connection' ? 'disconnect' : 'delete')} name={item.name}>
            {item.kind === 'connection' && (
              <FormControlLabel
                control={<Checkbox name="revoke" defaultChecked />}
                label={t('revokeProvider')}
              />
            )}
          </Confirm>
        </Stack>
      )}
    </Page>
  );
}
function BoxDetails({ item }: { item: Awaited<ReturnType<typeof clientLoader>> }) {
  const { t } = useTranslation();
  return (
    <>
      <Detail label={t('id')}>
        {item.id}
        <Copy value={item.id} />
      </Detail>
      <Detail label={t('created')}>
        <DateText value={item.createdAt} />
      </Detail>
      <Detail label={t('updated')}>
        <DateText value={item.updatedAt} />
      </Detail>
      {'state' in item.data && (
        <Detail label={t('status')}>
          <State value={item.data.state} />
        </Detail>
      )}
      {item.kind === 'connection' && (
        <>
          <Detail label={t('service')}>{item.data.serviceId}</Detail>
          <Detail label={t('accountName')}>{item.data.account}</Detail>
          <Detail label={t('scopes')}>{item.data.scopes.join(', ') || '—'}</Detail>
        </>
      )}
      {item.kind === 'secret' && (
        <Detail label={t('size')}>
          <Bytes value={item.data.bytes} />
        </Detail>
      )}
      {item.kind === 'object' && (
        <Detail label={t('size')}>
          <Bytes value={item.data.size} />
        </Detail>
      )}
    </>
  );
}
