import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { InputField } from '../form-fields';
import type { ReactNode } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { z } from 'zod';
import type { Route } from './+types/account';
import { canonical, fingerprint } from '../../../shared/authority';
import { Credential, Principal, listOf } from '../../../shared/contracts';
import { actionResult, api, formText, signedIn } from '../api';
import { custodyClient } from '../custody';
import { getIdentity, mergeWithPasskey } from '../keys';
import { Confirm, Copy, DateText, Detail, ErrorNotice, Fingerprint, Notice, Page, Panel, useTask } from '../components';
import i18n from '../i18n';

type CredentialView = z.infer<typeof Credential>;

const nameOf = (id: string) => api<{ name: string }>('/identities/' + id).then(identity => identity.name, () => null);

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const session = await signedIn(request);
  const id = session.principal!.id;
  const [principal, credentials, identity] = await Promise.all([
    api('/principals/' + id, { signal: request.signal }, Principal),
    api('/principals/' + id + '/credentials', { signal: request.signal }, listOf(Credential)),
    getIdentity(id),
  ]);
  // The fingerprint and the verified public keys need the private key in this browser; without it they are left out.
  // A verified public key its holder has since replaced is verified again.
  const client = identity ? await custodyClient(id) : null;
  const verified = client ? await Promise.all([...(await client.keyring()).values()]
    .map(async ({ binding, verifiedAt }) => ({ id: binding.principalId, name: await nameOf(binding.principalId),
      fingerprint: await fingerprint(binding), verifiedAt,
      changed: await client.inspectIdentity(binding.principalId)
        .then(current => canonical(current.binding) !== canonical(binding), () => false) }))) : null;
  return { session, principal, credentials: credentials.items,
    fingerprint: identity ? await fingerprint(identity.binding) : null,
    verified: verified?.sort((a, b) => b.verifiedAt.localeCompare(a.verifiedAt)) ?? null };
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const id = (await signedIn(request)).principal!.id, intent = formText(form, 'intent');
    if (intent === 'rename') await api('/principals/' + id, { method: 'PATCH', body: { name: formText(form, 'name') } });
    else if (intent === 'credential') await api('/principals/' + id + '/credentials/' + formText(form, 'credentialId'), { method: 'DELETE' });
    else if (intent === 'delete') {
      await api('/principals/' + id, { method: 'DELETE' });
      return redirect('/');
    } else return api<{ email: string }>('/account/merge/email', {
      method: 'POST',
      body: { email: formText(form, 'email'), locale: i18n.language === 'en' ? 'en' : 'ja' },
    });
    return { ok: true };
  });
}
// One rarely used operation: what it does on the left, its button on the right.
function Operation({ title, help, children }: { title: string; help: string; children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4 first:pt-0 last:pb-0">
    <div className="min-w-0 flex-1 basis-64 space-y-1">
      <h3 className="font-medium">{title}</h3>
      <p className="text-xs leading-relaxed text-muted-foreground">{help}</p>
    </div>
    {children}
  </div>;
}
export default function Account() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const task = useTask();
  const navigate = useNavigate();
  const { principal } = data;
  const adding = '/p/' + principal.id + '/settings/credentials/new?returnTo=/account&kind=';
  const signins = data.credentials.filter((item) => item.kind !== 'key');
  const keys = data.credentials.filter((item) => item.kind === 'key');
  const row = (item: CredentialView, status: string | null) => {
    const current = item.id === data.session.credentialId;
    return <li key={item.id} className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium wrap-anywhere">{item.name}</span>
          {current && <Badge variant="secondary">{t('inUse')}</Badge>}
        </div>
        <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
          {[t(item.kind === 'key' ? 'apiKey' : item.kind), status].filter(Boolean).join(' · ')} ·{' '}
          {item.lastUsedAt ? <>{t('lastUsed')}: <DateText value={item.lastUsedAt} /></>
            : <>{t('created')}: <DateText value={item.createdAt} /></>}
          {item.expiresAt && <> · {t('expires')}: <DateText value={item.expiresAt} /></>}
        </div>
      </div>
      {!current && <Confirm label={t('delete')} name={item.name}>
        <input type="hidden" name="intent" value="credential" />
        <input type="hidden" name="credentialId" value={item.id} />
      </Confirm>}
    </li>;
  };
  return (
    <Page title={t('account')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      {result && 'ok' in result && <Notice tone="success">{t('saved')}</Notice>}
      <Panel title={t('general')}>
        <Form method="post" className="flex min-w-0 flex-wrap items-end gap-2">
          <div className="min-w-0 flex-1 basis-64">
            <InputField name="name" label={t('name')} defaultValue={principal.name} key={principal.name} required />
          </div>
          <Button type="submit" name="intent" value="rename" variant="outline" size="lg">{t('save')}</Button>
        </Form>
        <Detail label={t('id')}>{principal.id}<Copy value={principal.id} /></Detail>
        {data.fingerprint && <Detail label={t('fingerprint')}><Fingerprint value={data.fingerprint} /></Detail>}
      </Panel>
      <Panel title={t('signinMethods')}>
        <ul className="divide-y divide-border">
          {signins.map((item) => row(item, item.kind === 'passkey' ? t(item.canOpen ? 'passkeyHolds' : 'passkeyLacks') : null))}
        </ul>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" asChild><Link to={adding + 'passkey'}>{t('addPasskey')}</Link></Button>
          {data.session.features.email && <Button variant="outline" asChild><Link to={adding + 'email'}>{t('addEmail')}</Link></Button>}
        </div>
      </Panel>
      <Panel title={t('apiKeys')}>
        {keys.length ? <ul className="divide-y divide-border">
          {keys.map((item) => row(item, t(item.canOpen ? 'apiKeyHolds' : 'apiKeyLacks')))}
        </ul> : <p className="leading-relaxed text-muted-foreground">{t('noApiKeys')}</p>}
        <div><Button variant="outline" asChild><Link to={adding + 'key'}>{t('issueKey')}</Link></Button></div>
      </Panel>
      <Panel title={t('verifiedIdentities')}>
        {data.verified && (data.verified.length ? <ul className="divide-y divide-border">
          {data.verified.map(item => <li key={item.id} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0">
            <div className="font-medium wrap-anywhere">{item.name ?? item.id}</div>
            <Detail label={t('id')}>{item.id}<Copy value={item.id} /></Detail>
            <Detail label={t('fingerprint')}><Fingerprint value={item.fingerprint} /></Detail>
            <Detail label={t('verifiedAt')}><DateText value={item.verifiedAt} /></Detail>
            {item.changed && <Notice tone="warning" action={<Button variant="outline" size="sm" asChild>
              <Link to={'/account/trust?principal=' + item.id}>{t('trustIdentity')}</Link>
            </Button>}>{t('keyChanged')}</Notice>}
          </li>)}
        </ul> : <p className="leading-relaxed text-muted-foreground">{t('noVerifiedIdentities')}</p>)}
        <div><Button variant="outline" asChild><Link to="/account/trust">{t('trustIdentity')}</Link></Button></div>
      </Panel>
      <Panel title={t('rarelyUsed')}>
        <div className="divide-y divide-border">
          <Operation title={t('merge')} help={t('mergeHelp')}>
            <Button variant="outline" loading={task.busy} onClick={() => task.run(async () => {
              const proof = await mergeWithPasskey();
              await navigate('/account/merge/' + proof.id);
            })}>{t('passkeySignin')}</Button>
            {data.session.features.email && <Form method="post" className="flex w-full min-w-0 flex-wrap items-end gap-2">
              <div className="min-w-0 flex-1 basis-64">
                <InputField name="email" type="email" label={t('email')} required />
              </div>
              <Button type="submit" variant="outline" size="lg">{t('sendLink')}</Button>
              {result && 'email' in result && <div className="w-full">
                <Notice tone="success">{t('emailSent', { email: result.email })}</Notice>
              </div>}
            </Form>}
          </Operation>
          <Operation title={t('export')} help={t('exportHelp')}>
            <Button variant="outline" asChild><a href={`/api/principals/${principal.id}/export`}>{t('download')}</a></Button>
          </Operation>
          <Operation title={t('deleteAccount')} help={t('deleteAccountHelp')}>
            <Confirm label={t('deleteAccount')} name={principal.name}>
              <input type="hidden" name="intent" value="delete" />
            </Confirm>
          </Operation>
        </div>
      </Panel>
    </Page>
  );
}
