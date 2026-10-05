import { useEffect, useState } from 'react';
import { Button, Alert } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { api, safeReturn } from '../api';
import { ErrorNotice, Page, Panel, useTask } from '../components';
export default function Email() {
  const { t } = useTranslation();
  const task = useTask();
  const [proof, setProof] = useState<{ challengeId: string; token: string } | null>(null);
  useEffect(() => {
    const hash = new URLSearchParams(window.location.hash.slice(1));
    const challengeId = hash.get('challenge'),
      token = hash.get('token');
    if (challengeId && token) {
      setProof({ challengeId, token });
      history.replaceState(null, '', window.location.pathname);
    }
  }, []);
  return (
    <Page title={t('emailVerify')} narrow>
      <ErrorNotice error={task.error} />
      <Panel>
        {proof ? (
          <Button
            variant="contained"
            loading={task.busy}
            onClick={() =>
              task.run(async () => {
                const result = await api<{ returnTo: string; mergeProof?: string }>('/auth/email/verify', {
                  method: 'POST',
                  body: proof,
                });
                window.location.assign(
                  result.mergeProof ? '/account/merge/' + result.mergeProof : safeReturn(result.returnTo),
                );
              })
            }
          >
            {t('emailContinue')}
          </Button>
        ) : (
          <Alert severity="info">{t('emailInvalid')}</Alert>
        )}
      </Panel>
    </Page>
  );
}
