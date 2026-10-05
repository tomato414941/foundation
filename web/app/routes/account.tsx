import { useEffect, useState } from 'react';
import { Form, Link, useActionData, useLoaderData, useNavigate, useRevalidator } from 'react-router';
import { Alert, Button, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/account';
import { actionResult, api, formText, signedIn } from '../api';
import { authenticate, getKey, mergeWithPasskey } from '../keys';
import { Copy, Detail, ErrorNotice, Page, Panel, useTask } from '../components';
import i18n from '../i18n';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  return signedIn(request);
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    return api<{ email: string }>('/account/merge/email', {
      method: 'POST',
      body: { email: formText(form, 'email'), locale: i18n.language === 'en' ? 'en' : 'ja' },
    });
  });
}
export default function Account() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const principal = data.principal!;
  const task = useTask();
  const navigate = useNavigate();
  const revalidator = useRevalidator();
  const [unlocked, setUnlocked] = useState(false);
  useEffect(() => {
    void getKey(principal.id).then((key) => setUnlocked(!!key));
  }, [principal.id]);
  const prefix = '/p/' + principal.id + '/settings/';
  return (
    <Page title={t('account')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <Panel title={principal.name}>
        <Detail label={t('id')}>
          {principal.id}
          <Copy value={principal.id} />
        </Detail>
        <Button component={Link} to={prefix + 'general'}>
          {t('general')}
        </Button>
        <Button component={Link} to={prefix + 'credentials'}>
          {t('credentials')}
        </Button>
      </Panel>
      <Panel title={t('secrets')}>
        <Alert severity={unlocked ? 'success' : 'info'}>{t(unlocked ? 'keyReady' : 'keyLocked')}</Alert>
        <Stack direction="row" spacing={2}>
          <Button
            variant="outlined"
            loading={task.busy}
            onClick={() =>
              task.run(async () => {
                const auth = await authenticate(principal.id);
                setUnlocked(auth.encrypted);
                if (!auth.encrypted) throw new Error('key unavailable');
                await revalidator.revalidate();
              })
            }
          >
            {t('unlock')}
          </Button>
          <Button component={Link} to={prefix + 'credentials/new'}>
            {t('addPasskey')}
          </Button>
        </Stack>
      </Panel>
      <Panel title={t('merge')}>
        <Typography color="text.secondary">{t('mergeHelp')}</Typography>
        <Button
          variant="outlined"
          loading={task.busy}
          onClick={() =>
            task.run(async () => {
              const proof = await mergeWithPasskey();
              await navigate('/account/merge/' + proof.id);
            })
          }
        >
          {t('passkeySignin')}
        </Button>
        {data.features.email && (
          <Form method="post">
            <Stack spacing={2}>
              <TextField name="email" type="email" label={t('email')} required fullWidth />
              {result && 'email' in result && (
                <Alert severity="success">{t('emailSent', { email: result.email })}</Alert>
              )}
              <Button type="submit">{t('sendLink')}</Button>
            </Stack>
          </Form>
        )}
      </Panel>
    </Page>
  );
}
