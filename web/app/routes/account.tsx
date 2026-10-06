import { Button } from '../components/ui/button';
import { InputField } from '../form-fields';
import { Notice } from '../components';
import { useEffect, useState } from 'react';
import { Form, Link, useActionData, useLoaderData, useNavigate, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/account';
import { actionResult, api, formText, signedIn } from '../api';
import { authenticate, getKey, mergeWithPasskey, migrateEncryptionKey } from '../keys';
import { Copy, Detail, ErrorNotice, Page, Panel, useTask } from '../components';
import i18n from '../i18n';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  return signedIn(request);
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    return api<{
      email: string;
    }>('/account/merge/email', {
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
  const [migrationProgress, setMigrationProgress] = useState<string | null>(null);
  const [migrated, setMigrated] = useState(false);
  useEffect(() => {
    void getKey(principal.id, principal.publicKey).then((key) => setUnlocked(!!key));
  }, [principal.id, principal.publicKey]);
  const prefix = '/p/' + principal.id + '/settings/';
  return (
    <Page title={t('account')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <Panel title={principal.name}>
        <Detail label={t('id')}>
          {principal.id}
          <Copy value={principal.id} />
        </Detail>
        <Button variant="ghost" asChild>
          <Link to={prefix + 'general'}>{t('general')}</Link>
        </Button>
        <Button variant="ghost" asChild>
          <Link to={prefix + 'credentials'}>{t('credentials')}</Link>
        </Button>
      </Panel>
      <Panel title={t('secrets')}>
        <Notice tone={unlocked ? 'success' : 'info'}>{t(unlocked ? 'keyReady' : 'keyLocked')}</Notice>
        <div className="flex min-w-0 flex-wrap items-center gap-4">
          <Button
            loading={task.busy}
            onClick={() =>
              task.run(async () => {
                const auth = await authenticate(principal.id);
                setUnlocked(auth.encrypted);
                if (!auth.encrypted) throw new Error('key unavailable');
                await revalidator.revalidate();
              })
            }
            variant="outline"
          >
            {t('unlock')}
          </Button>
          <Button variant="ghost" asChild>
            <Link to={prefix + 'credentials/new'}>{t('addPasskey')}</Link>
          </Button>
        </div>
      </Panel>
      {(principal.publicKey?.crv === 'X25519' || migrated) && (
        <Panel title={t('migrationTitle')}>
          {migrated ? <Notice tone="success">{t('migrationComplete')}</Notice> : <>
            <p className="leading-relaxed text-muted-foreground">{t('migrationHelp')}</p>
            {migrationProgress && <p role="status">{migrationProgress}</p>}
            <Button loading={task.busy} onClick={() => task.run(async () => {
              try {
                await migrateEncryptionKey(principal.id, step => setMigrationProgress(t(
                  step.phase === 'passkey' ? 'migrationPasskey' : step.phase === 'secrets' ? 'migrationSecrets' : 'migrationSaving',
                  { name: step.name, index: step.index, count: step.total },
                )));
                setMigrated(true);
                setUnlocked(true);
                await revalidator.revalidate();
              } finally { setMigrationProgress(null); }
            })}>{t('migrationStart')}</Button>
          </>}
        </Panel>
      )}
      <Panel title={t('merge')}>
        <p className="leading-relaxed text-muted-foreground">{t('mergeHelp')}</p>
        <Button
          loading={task.busy}
          onClick={() =>
            task.run(async () => {
              const proof = await mergeWithPasskey();
              await navigate('/account/merge/' + proof.id);
            })
          }
          variant="outline"
        >
          {t('passkeySignin')}
        </Button>
        {data.features.email && (
          <Form method="post">
            <div className="flex min-w-0 flex-col gap-4">
              <InputField name="email" type="email" label={t('email')} required />
              {result && 'email' in result && (
                <Notice tone={'success'}>{t('emailSent', { email: result.email })}</Notice>
              )}
              <Button type="submit" variant="ghost">
                {t('sendLink')}
              </Button>
            </div>
          </Form>
        )}
      </Panel>
    </Page>
  );
}
