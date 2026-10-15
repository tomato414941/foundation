import { useState } from 'react';
import { useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import type { Route } from './+types/oauth-authorize';
import { SelectItem } from '../components/ui/select';
import { SelectField } from '../form-fields';
import { Button } from '../components/ui/button';
import { api, signedIn } from '../api';
import { ErrorNotice, Notice, Page, Panel, useTask } from '../components';

const Client = z.object({ name: z.string(), host: z.string() });
const Authorized = z.object({ redirectTo: z.string() });
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  const account = await signedIn(request);
  const query = new URL(request.url).searchParams;
  const input = {
    clientId: query.get('client_id') ?? '',
    redirectUri: query.get('redirect_uri') ?? '',
    codeChallenge: query.get('code_challenge') ?? '',
    state: query.get('state') ?? undefined,
    resource: query.get('resource') ?? undefined,
  };
  if (query.get('response_type') !== 'code' || query.get('code_challenge_method') !== 'S256' ||
    !input.clientId || !input.redirectUri || !input.codeChallenge)
    return { account, input, client: null };
  const search = new URLSearchParams({ client_id: input.clientId, redirect_uri: input.redirectUri });
  const client = await api('/oauth/client?' + search, { signal: request.signal }, Client).catch(() => null);
  return { account, input, client };
}
export default function OAuthAuthorizePage() {
  const { t } = useTranslation();
  const { account, input, client } = useLoaderData<typeof clientLoader>();
  const candidates = account.principals.filter((item) => item.permissions.includes('manage_credentials'));
  const [principalId, setPrincipalId] = useState(account.principal?.id ?? '');
  const task = useTask();
  if (!client)
    return (
      <Page title={t('oauthTitle')} narrow>
        <Panel>
          <Notice tone="error">{t('oauthInvalid')}</Notice>
        </Panel>
      </Page>
    );
  const deny = () => {
    const target = new URL(input.redirectUri);
    target.searchParams.set('error', 'access_denied');
    if (input.state !== undefined) target.searchParams.set('state', input.state);
    window.location.assign(target.href);
  };
  return (
    <Page title={t('oauthTitle')} narrow>
      <ErrorNotice error={task.error} />
      <Panel>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void task.run(async () => {
              const { redirectTo } = await api('/oauth/authorizations', {
                method: 'POST',
                body: { ...input, codeChallengeMethod: 'S256', principalId },
              }, Authorized);
              window.location.assign(redirectTo);
            });
          }}
        >
          <div className="flex min-w-0 flex-col gap-6">
            <p>{t('oauthAsk', { name: client.name, host: client.host })}</p>
            <SelectField name="principalId" label={t('oauthAs')} value={principalId} onValueChange={setPrincipalId}>
              {candidates.map((item) => (
                <SelectItem key={item.id} value={item.id}>
                  {item.name}
                </SelectItem>
              ))}
            </SelectField>
            <p className="text-sm text-muted-foreground">{t('oauthScope')}</p>
            <div className="flex flex-wrap items-center gap-2 pt-2">
              <Button type="submit" loading={task.busy}>
                {t('allow')}
              </Button>
              <Button type="button" variant="outline" onClick={deny}>
                {t('deny')}
              </Button>
            </div>
          </div>
        </form>
      </Panel>
    </Page>
  );
}
