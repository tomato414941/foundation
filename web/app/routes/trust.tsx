import { Form, Link, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/trust';
import { fingerprint } from '../../../shared/authority';
import { actionResult, api, formText, signedIn } from '../api';
import { custodyClient } from '../custody';
import { getIdentity, requireKeys, resealNow } from '../keys';
import { ResealingNotice } from '../resealing-notice';
import { InputField } from '../form-fields';
import { Button } from '../components/ui/button';
import { Copy, DateText, Detail, ErrorNotice, Notice, Page, Panel, SaveBar } from '../components';

const nameOf = (id: string) => api<{ name: string }>('/identities/' + id).then(identity => identity.name, () => null);

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const recipient = new URL(request.url).searchParams.get('principal') ?? '';
  // A fingerprint the other party linked comes in the fragment, which never reaches the server. It is kept for this tab
  // until the public key is verified, so that signing in on the way keeps it.
  const linked = new URLSearchParams(window.location.hash.slice(1)).get('fingerprint');
  if (recipient && linked) sessionStorage.setItem('foundation.fingerprint.principal.' + recipient, linked);
  const id = (await signedIn(request)).principal!.id;
  const recipientFingerprint = recipient ? sessionStorage.getItem('foundation.fingerprint.principal.' + recipient) ?? '' : '';
  // Without the private key in this browser, the page leaves out what only the private key can show; verifying asks
  // for a passkey.
  if (!(await getIdentity(id))) return { id, fingerprint: null, recipient, recipientFingerprint, verified: null };
  const client = await custodyClient();
  const verified = await Promise.all([...(await client.keyring()).values()].map(async ({ binding, verifiedAt }) => ({
    id: binding.principalId, name: await nameOf(binding.principalId), fingerprint: await fingerprint(binding), verifiedAt })));
  return { id, fingerprint: await fingerprint(client.binding), recipient, recipientFingerprint,
    verified: verified.sort((a, b) => b.verifiedAt.localeCompare(a.verifiedAt)) };
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), principalId = formText(form, 'principalId');
    await requireKeys();
    const client = await custodyClient();
    await client.trustIdentity(principalId, formText(form, 'fingerprint'));
    sessionStorage.removeItem('foundation.fingerprint.principal.' + principalId);
    // What the verified public key lets this browser seal is sealed now, rather than the next time Foundation opens.
    const outcome = await resealNow(client.binding.principalId);
    return { verified: (await nameOf(principalId)) ?? principalId, resealed: outcome?.done ?? 0 };
  });
}
// Shown in groups of four for comparing by eye; copying keeps it whole.
function Fingerprint({ value }: { value: string }) {
  const [algorithm, digest = ''] = value.split(':');
  return <>
    <span className="font-mono">{algorithm}:{digest.match(/.{4}/g)?.map((group, index) =>
      <span key={index} className="ml-1.5 inline-block">{group}</span>)}</span>
    <Copy value={value} />
  </>;
}
export default function Trust() {
  const { t } = useTranslation(), data = useLoaderData<typeof clientLoader>(), result = useActionData<typeof clientAction>();
  const done = result && 'verified' in result ? result : null;
  return <Page title={t('trustIdentity')} narrow>
    <ErrorNotice error={result && 'error' in result ? result.error : null} />
    {done && <Notice tone="success">
      <p>{t('identityVerified', { name: done.verified })}</p>
      {done.resealed > 0 && <p>{t('resealed', { count: done.resealed })}</p>}
    </Notice>}
    <ResealingNotice principalId={data.id} />
    <Panel title={t('myIdentity')}>
      <Detail label={t('id')}>{data.id}<Copy value={data.id} /></Detail>
      {data.fingerprint && <Detail label={t('fingerprint')}><Fingerprint value={data.fingerprint} /></Detail>}
    </Panel>
    {done ? <div>
      <Button variant="outline" asChild><Link to="/account/trust">{t('verifyAnother')}</Link></Button>
    </div> : <Form method="post"><div className="flex flex-col gap-6">
      <p className="text-sm leading-relaxed text-muted-foreground">{t('trustIdentityHelp')}</p>
      <InputField name="principalId" label={t('recipient')} required defaultValue={data.recipient} />
      <InputField name="fingerprint" label={t('fingerprint')} required autoComplete="off" minLength={71} maxLength={71}
        defaultValue={data.recipientFingerprint} />
      <SaveBar back="/account" label="trustIdentity" />
    </div></Form>}
    {data.verified && <Panel title={t('verifiedIdentities')}>
      {data.verified.length ? <ul className="divide-y divide-border">
        {data.verified.map(item => <li key={item.id} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0">
          <div className="font-medium wrap-anywhere">{item.name ?? item.id}</div>
          <Detail label={t('id')}>{item.id}<Copy value={item.id} /></Detail>
          <Detail label={t('fingerprint')}><Fingerprint value={item.fingerprint} /></Detail>
          <Detail label={t('verifiedAt')}><DateText value={item.verifiedAt} /></Detail>
        </li>)}
      </ul> : <p className="leading-relaxed text-muted-foreground">{t('noVerifiedIdentities')}</p>}
    </Panel>}
  </Page>;
}
