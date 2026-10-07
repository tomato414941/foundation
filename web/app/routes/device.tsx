import { useState } from 'react';
import { useLoaderData, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/device';
import { SelectItem } from '../components/ui/select';
import { InputField, SelectField } from '../form-fields';
import { Button } from '../components/ui/button';
import { DeviceRequest } from '../../../shared/contracts';
import { api, signedIn } from '../api';
import { seal, encode } from '../../../shared/encryption';
import { issueKey } from '../keys';
import { DateText, Detail, ErrorNotice, Notice, Page, Panel, useTask } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const account = await signedIn(request);
  const device = await api('/auth/devices/' + params.id, { signal: request.signal }, DeviceRequest);
  return { device, account };
}
export default function DevicePage() {
  const { t } = useTranslation();
  const { device, account } = useLoaderData<typeof clientLoader>();
  const candidates = account.principals.filter((item) => item.permissions.includes('credentials'));
  const [principalId, setPrincipalId] = useState(account.principal?.id ?? '');
  const [code, setCode] = useState('');
  const task = useTask();
  const revalidator = useRevalidator();
  const done = device.state === 'approved';
  return (
    <Page title={t('deviceTitle')} narrow>
      <ErrorNotice error={task.error} />
      <Panel>
        {done ? (
          <Notice tone="success">{t('deviceDone', { name: device.name })}</Notice>
        ) : (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void task.run(async () => {
                const principal = candidates.find((item) => item.id === principalId);
                if (!principal) return;
                await api(`/auth/devices/${device.id}/approve`, {
                  method: 'POST',
                  body: { code, principalId: principal.id },
                });
                const { token } = await issueKey(principal, device.name, null);
                const sealed = await seal(encode(token), [{ id: device.id, publicKey: device.publicKey }], 'device:' + device.id);
                await api(`/auth/devices/${device.id}/complete`, { method: 'POST', body: { sealed } });
                await revalidator.revalidate();
              });
            }}
          >
            <div className="flex min-w-0 flex-col gap-6">
              <p>{t('deviceAsk', { name: device.name })}</p>
              <Detail label={t('expires')}>
                <DateText value={device.expiresAt} />
              </Detail>
              <InputField
                name="code"
                label={t('code')}
                hint={t('codeHelp')}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                autoComplete="one-time-code"
                required
              />
              <SelectField name="principalId" label={t('deviceAs')} value={principalId} onValueChange={setPrincipalId}>
                {candidates.map((item) => (
                  <SelectItem key={item.id} value={item.id}>
                    {item.name}
                  </SelectItem>
                ))}
              </SelectField>
              <div className="flex flex-wrap items-center gap-2 pt-2">
                <Button type="submit" loading={task.busy}>
                  {t('allow')}
                </Button>
              </div>
            </div>
          </form>
        )}
      </Panel>
    </Page>
  );
}
