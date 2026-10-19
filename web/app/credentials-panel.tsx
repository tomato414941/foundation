import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Button } from './components/ui/button';
import { Badge } from './components/ui/badge';
import { Confirm, DateText, Notice, Panel } from './components';
import type { PrincipalView } from '../../shared/contracts';
import type { z } from 'zod';
import type { Credential } from '../../shared/contracts';

type CredentialView = z.infer<typeof Credential>;

// Every way into a principal, with whether it can open encrypted values.
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
  const kind = (item: CredentialView) =>
    t(item.kind === 'key' ? 'apiKey' : item.kind === 'email' ? 'email' : 'passkey');
  return (
    <Panel title={t('credentials')}>
      {!principal.publicKey && <Notice tone="info">{t('keyMissing')}</Notice>}
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
