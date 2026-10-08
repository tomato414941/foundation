import { useEffect, useState } from 'react';
import { Link, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Button } from './components/ui/button';
import { Badge } from './components/ui/badge';
import { Confirm, DateText, ErrorNotice, Notice, Panel, useTask } from './components';
import { authenticate, getKey, handKey } from './keys';
import type { PrincipalView } from '../../shared/contracts';
import type { z } from 'zod';
import type { Credential } from '../../shared/contracts';

type CredentialView = z.infer<typeof Credential>;

// Every way into a principal, with whether it can open secrets. The state of this browser's key
// sits above the list, since it decides what the buttons below can do.
export function CredentialsPanel({
  principal,
  items,
  currentId,
}: {
  principal: PrincipalView;
  items: CredentialView[];
  currentId: string | null;
}) {
  const { t } = useTranslation();
  const [unlocked, setUnlocked] = useState(false);
  const task = useTask();
  const revalidator = useRevalidator();
  useEffect(() => {
    void getKey(principal.id, principal.publicKey).then((key) => setUnlocked(!!key));
  }, [principal.id, principal.publicKey, items]);
  const kind = (item: CredentialView) =>
    t(item.kind === 'key' ? 'apiKey' : item.kind === 'email' ? 'email' : 'passkey');
  return (
    <Panel title={t('credentials')}>
      <ErrorNotice error={task.error} />
      {!principal.publicKey ? (
        <Notice tone="info">{t('keyMissing')}</Notice>
      ) : (
        <div className="flex min-w-0 flex-wrap items-center gap-4">
          <Notice tone={unlocked ? 'success' : 'info'}>{t(unlocked ? 'keyReady' : 'keyLocked')}</Notice>
          {!unlocked && (
            <Button
              variant="outline"
              loading={task.busy}
              onClick={() =>
                task.run(async () => {
                  const auth = await authenticate(principal.id);
                  setUnlocked(auth.encrypted);
                  await revalidator.revalidate();
                })
              }
            >
              {t('unlock')}
            </Button>
          )}
        </div>
      )}
      <ul className="divide-y divide-border">
        {items.map((item) => {
          const current = item.id === currentId;
          return (
            <li key={item.id} className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0">
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium wrap-anywhere">{item.name}</span>
                  {current && <Badge variant="secondary">{t('inUse')}</Badge>}
                </div>
                <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                  {kind(item)} · {t(item.canOpen ? 'canOpen' : 'cannotOpen')} ·{' '}
                  {item.lastUsedAt ? (
                    <>
                      {t('lastUsed')}: <DateText value={item.lastUsedAt} />
                    </>
                  ) : (
                    <>
                      {t('created')}: <DateText value={item.createdAt} />
                    </>
                  )}
                  {item.expiresAt && (
                    <>
                      {' '}
                      · {t('expires')}: <DateText value={item.expiresAt} />
                    </>
                  )}
                </div>
              </div>
              {item.kind === 'passkey' && !item.canOpen && unlocked && (
                <Button
                  variant="outline"
                  size="sm"
                  loading={task.busy}
                  onClick={() =>
                    task.run(async () => {
                      await handKey(principal.id, item.id);
                      await revalidator.revalidate();
                    })
                  }
                >
                  {t('handKey')}
                </Button>
              )}
              {!current && (
                <Confirm label={t('delete')} name={item.name}>
                  <input type="hidden" name="intent" value="credential" />
                  <input type="hidden" name="credentialId" value={item.id} />
                </Confirm>
              )}
            </li>
          );
        })}
      </ul>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="default" asChild>
          <Link to="new?kind=passkey">{t('addPasskey')}</Link>
        </Button>
        <Button variant="outline" asChild>
          <Link to="new?kind=email">{t('addEmail')}</Link>
        </Button>
        <Button variant="outline" asChild>
          <Link to="new?kind=key">{t('issueKey')}</Link>
        </Button>
      </div>
    </Panel>
  );
}
