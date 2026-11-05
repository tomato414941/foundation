import { useEffect, useState } from 'react';
import { Form, Link, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Button } from './components/ui/button';
import { Badge } from './components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './components/ui/dialog';
import { Confirm, DateText, Notice, Panel } from './components';
import { InputField } from './form-fields';
import type { PrincipalView } from '../../shared/contracts';
import type { z } from 'zod';
import type { Credential } from '../../shared/contracts';

type CredentialView = z.infer<typeof Credential>;

function Rename({ item }: { item: CredentialView }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const navigation = useNavigation();
  useEffect(() => {
    if (navigation.state === 'loading') setOpen(false);
  }, [navigation.state]);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost">{t('rename')}</Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false}>
        <Form method="post" className="space-y-5">
          <DialogHeader>
            <DialogTitle>{t('renameCredential')}</DialogTitle>
            <DialogDescription>{t('renameCredentialHelp')}</DialogDescription>
          </DialogHeader>
          <input type="hidden" name="intent" value="renameCredential" />
          <input type="hidden" name="credentialId" value={item.id} />
          <InputField name="name" label={t('name')} defaultValue={item.name} required maxLength={200} autoFocus />
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              {t('cancel')}
            </Button>
            <Button type="submit" loading={navigation.state === 'submitting'}>
              {t('save')}
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

// Sign-in methods or API keys of a principal, each with what it can do and when it was used.
export function CredentialList({
  items,
  currentId,
  status,
}: {
  items: CredentialView[];
  currentId: string | null;
  status: (item: CredentialView) => string;
}) {
  const { t } = useTranslation();
  return (
    <ul className="divide-y divide-border">
      {items.map((item) => {
        const current = item.id === currentId;
        return (
          <li key={item.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 py-4 first:pt-0 last:pb-0">
            <div className="min-w-0 flex-1 basis-56 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium wrap-anywhere">{item.name}</span>
                {current && <Badge variant="secondary">{t('inUse')}</Badge>}
              </div>
              <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                {status(item)} ·{' '}
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
            <div className="flex items-center gap-1">
              <Rename item={item} />
              {!current && (
                <Confirm label={t('delete')} name={item.name}>
                  <input type="hidden" name="intent" value="credential" />
                  <input type="hidden" name="credentialId" value={item.id} />
                </Confirm>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// Every way into another principal, with whether it can open encrypted values.
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
      <CredentialList items={items} currentId={currentId}
        status={(item) => kind(item) + ' · ' + t(item.canOpen ? 'canOpen' : 'cannotOpen')} />
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" asChild>
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
