import { Button } from '../components/ui/button';
import { InputField } from '../form-fields';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { redirect, useLoaderData, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/keys';
import { ApiFailure, errorCode, safeReturn, session } from '../api';
import { getIdentity, openKeys, receiveKeys, registerPasskey, startReceiving } from '../keys';
import type { Receiving } from '../keys';
import { Copy, DateText, Detail, ErrorNotice, Page, Panel, useTask } from '../components';

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const data = await session(request);
  const back = safeReturn(new URL(request.url).searchParams.get('returnTo'));
  if (!data.principal) throw redirect('/signin?returnTo=' + encodeURIComponent(back));
  if (await getIdentity(data.principal.id)) throw redirect(back);
  return { principal: data.principal, back };
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
  const { principal, back } = useLoaderData<typeof clientLoader>();
  const task = useTask();
  const [name, setName] = useState('');
  const [receiving, setReceiving] = useState<Receiving | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const navigate = useNavigate();
  const done = () => navigate(back, { replace: true });
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
        </div>
      </Panel>
    </Page>
  );
}
