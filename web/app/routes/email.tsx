import { Button } from '../components/ui/button';
import { Notice } from '../components';
import { InputField } from '../form-fields';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api, safeReturn } from '../api';
import { ErrorNotice, Page, Panel, useTask } from '../components';
export default function Email() {
  const { t } = useTranslation();
  const task = useTask();
  const [proof, setProof] = useState<{
    challengeId: string;
    token: string;
  } | null>(null);
  const [registration, setRegistration] = useState<{ proof: string; email: string } | null>(null);
  useEffect(() => {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const challengeId = hash.get('challenge'),
      token = hash.get('token');
    if (challengeId && token) {
      setProof({ challengeId, token });
      history.replaceState(null, '', window.location.pathname);
    }
  }, []);
  if (registration)
    return (
      <Page title={t('signup')} narrow>
        <ErrorNotice error={task.error} />
        <Panel>
          <form
            className="flex min-w-0 flex-col gap-6"
            onSubmit={(event) => {
              event.preventDefault();
              const name = String(new FormData(event.currentTarget).get('name') ?? '').trim();
              task.run(async () => {
                const result = await api<{ returnTo: string }>('/auth/email/register', {
                  method: 'POST',
                  body: { proof: registration.proof, ...(name ? { name } : {}) },
                });
                window.location.assign(safeReturn(result.returnTo));
              });
            }}
          >
            <p className="leading-relaxed text-muted-foreground">
              {t('emailNotRegistered', { email: registration.email })}
            </p>
            <InputField
              label={t('name')}
              name="name"
              defaultValue={registration.email.split('@')[0]}
              required
              autoFocus
            />
            <div className="flex flex-wrap gap-2">
              <Button type="submit" loading={task.busy} variant="default">
                {t('signup')}
              </Button>
              <Button type="button" variant="outline" onClick={() => window.location.assign('/signin')}>
                {t('cancel')}
              </Button>
            </div>
          </form>
        </Panel>
      </Page>
    );
  return (
    <Page title={t('emailVerify')} narrow>
      <ErrorNotice error={task.error} />
      <Panel>
        {proof ? (
          <Button
            loading={task.busy}
            onClick={() =>
              task.run(async () => {
                const result = await api<{
                  returnTo: string;
                  mergeProof?: string;
                  registrationProof?: string;
                  email?: string;
                }>('/auth/email/verify', {
                  method: 'POST',
                  body: proof,
                });
                if (result.registrationProof && result.email) {
                  setRegistration({ proof: result.registrationProof, email: result.email });
                  return;
                }
                window.location.assign(
                  result.mergeProof
                    ? '/account/merge/' + result.mergeProof
                    : safeReturn(result.returnTo),
                );
              })
            }
            variant="default"
          >
            {t('emailContinue')}
          </Button>
        ) : (
          <Notice tone={'info'}>{t('emailInvalid')}</Notice>
        )}
      </Panel>
    </Page>
  );
}
