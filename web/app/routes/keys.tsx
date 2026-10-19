import { Button } from '../components/ui/button';
import { InputField } from '../form-fields';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { redirect, useLoaderData, useNavigate, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/keys';
import { ApiFailure, api, errorCode, safeReturn, session } from '../api';
import { heldKeys, openKeys, receiveKeys, registerPasskey, resetKeys, startReceiving } from '../keys';
import type { Receiving } from '../keys';
import { Copy, DateText, Detail, ErrorNotice, Page, Panel, useTask } from '../components';

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const data = await session(request);
  const back = safeReturn(new URL(request.url).searchParams.get('returnTo'));
  if (!data.principal) throw redirect('/signin?returnTo=' + encodeURIComponent(back));
  if (await heldKeys(data.principal)) throw redirect(back);
  return { principal: data.principal, reset: data.keyReset, back };
}
// One action with what it does on the left and its button on the right, as on the account page.
function Way({ title, help, children }: { title: string; help: string; children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4 first:pt-0 last:pb-0">
    <div className="min-w-0 flex-1 basis-64 space-y-1">
      <h3 className="font-medium">{title}</h3>
      <p className="text-xs leading-relaxed text-muted-foreground">{help}</p>
    </div>
    {children}
  </div>;
}
export default function Keys() {
  const { t } = useTranslation();
  const { principal, reset, back } = useLoaderData<typeof clientLoader>();
  const task = useTask();
  const [name, setName] = useState('');
  const [receiving, setReceiving] = useState<Receiving | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const navigate = useNavigate();
  const revalidator = useRevalidator();
  const done = () => navigate(back, { replace: true });
  const resetPath = '/principals/' + principal.id + '/key-reset';
  useEffect(() => {
    if (!receiving) return;
    // Asks again only after an answer, since the server hands the sealed key out once.
    let stopped = false, timer: ReturnType<typeof setTimeout>;
    const poll = () => void receiveKeys(receiving, principal.id).then(received => {
      if (stopped) return;
      if (received) void done();
      else timer = setTimeout(poll, 2000);
    }, (error: unknown) => {
      if (stopped) return;
      setFailed(errorCode(error));
      setReceiving(null);
    });
    timer = setTimeout(poll, 2000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [receiving, principal.id]);
  if (!principal.publicKey) return (
    <Page title={t('keysTitle')} narrow>
      <p className="leading-relaxed text-muted-foreground">{t('keysCreateDescription')}</p>
      <ErrorNotice error={task.error} />
      <Panel>
        <form className="flex min-w-0 flex-wrap items-end gap-2" onSubmit={(event) => {
          event.preventDefault();
          void task.run(async () => {
            if (!(await registerPasskey(name, principal)).encrypted) throw new ApiFailure('key_unsupported');
            await done();
          });
        }}>
          <div className="min-w-0 flex-1 basis-64">
            <InputField label={t('name')} value={name} onChange={(event) => setName(event.target.value)} required />
          </div>
          <Button type="submit" size="lg" loading={task.busy}>{t('addPasskey')}</Button>
        </form>
      </Panel>
    </Page>
  );
  const cancel = <Button variant="ghost" loading={task.busy} onClick={() => task.run(async () => {
    await api(resetPath, { method: 'DELETE' });
    setConfirming(false);
    await revalidator.revalidate();
  })}>{t('cancelReset')}</Button>;
  return (
    <Page title={t('keysTitle')} narrow>
      <p className="leading-relaxed text-muted-foreground">{t('keysDescription')}</p>
      <ErrorNotice error={task.error ?? failed} />
      <Panel>
        <div className="divide-y divide-border">
          <Way title={t('passkeyOpen')} help={t('passkeyOpenHelp')}>
            <Button loading={task.busy} onClick={() => task.run(async () => { await openKeys(principal.id); await done(); })}>
              {t('passkeyOpen')}
            </Button>
          </Way>
          <Way title={t('receiveKeys')} help={t('receiveKeysHelp')}>
            {!receiving && <Button variant="outline" loading={task.busy} onClick={() => task.run(async () => {
              setFailed(null);
              setReceiving(await startReceiving(t('thisBrowser')));
            })}>{t('receiveStart')}</Button>}
            {receiving && <div className="flex w-full min-w-0 flex-col gap-3">
              <p className="leading-relaxed">{t('receiveKeysSteps')}</p>
              <Detail label={t('url')}>{receiving.url}<Copy value={receiving.url} /></Detail>
              <Detail label={t('code')}>{receiving.code.slice(0, 4) + '-' + receiving.code.slice(4)}</Detail>
              <Detail label={t('expires')}><DateText value={receiving.expiresAt} /></Detail>
            </div>}
          </Way>
          <Way title={t('resetKeys')} help={t('resetKeysHelp')}>
            {!reset && !confirming && <Button variant="outline" onClick={() => setConfirming(true)}>{t('resetStart')}</Button>}
            {!reset && confirming && <div className="flex w-full min-w-0 flex-col gap-3">
              <p className="leading-relaxed">{t('resetIntro')}</p>
              <ul className="list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-muted-foreground">
                {['resetValues', 'resetResults', 'resetApiKeys', 'resetVerification', 'resetDelay'].map(key => <li key={key}>{t(key)}</li>)}
              </ul>
              <div className="flex flex-wrap gap-2">
                <Button variant="destructive" loading={task.busy} onClick={() => task.run(async () => {
                  await api(resetPath, { method: 'POST', body: {} });
                  await revalidator.revalidate();
                })}>{t('requestReset')}</Button>
                <Button variant="ghost" onClick={() => setConfirming(false)}>{t('cancel')}</Button>
              </div>
            </div>}
            {reset && Date.parse(reset.readyAt) > Date.now() && <div className="flex w-full min-w-0 flex-col gap-3">
              <p className="leading-relaxed">{t('resetRequested')}</p>
              <Detail label={t('resetReadyAt')}><DateText value={reset.readyAt} /></Detail>
              <div>{cancel}</div>
            </div>}
            {reset && Date.parse(reset.readyAt) <= Date.now() && <form className="flex w-full min-w-0 flex-col gap-3" onSubmit={(event) => {
              event.preventDefault();
              void task.run(async () => {
                await resetKeys(name, principal.id);
                await done();
              });
            }}>
              <p className="leading-relaxed">{t('resetReady')}</p>
              <div className="flex min-w-0 flex-wrap items-end gap-2">
                <div className="min-w-0 flex-1 basis-64">
                  <InputField label={t('name')} value={name} onChange={(event) => setName(event.target.value)} required />
                </div>
                <Button type="submit" size="lg" loading={task.busy}>{t('resetWithPasskey')}</Button>
              </div>
              <div>{cancel}</div>
            </form>}
          </Way>
        </div>
      </Panel>
    </Page>
  );
}
