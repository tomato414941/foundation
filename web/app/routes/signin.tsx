import { Button } from '../components/ui/button';
import { Separator } from '../components/ui/separator';
import { InputField } from '../form-fields';
import { Notice } from '../components';
import { Fingerprint as FingerprintIcon } from 'lucide-react';
import { useState } from 'react';
import { Form, useActionData, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/signin';
import { actionResult, api, formText, safeReturn, session } from '../api';
import { authenticate, registerPasskey } from '../keys';
import { ErrorNotice, Page, Panel, useTask } from '../components';
import i18n from '../i18n';
export async function clientLoader() {
  return session();
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    return api<{
      email: string;
    }>('/auth/email', {
      method: 'POST',
      body: {
        email: formText(form, 'email'),
        locale: i18n.language === 'en' ? 'en' : 'ja',
        returnTo: safeReturn(formText(form, 'returnTo')),
      },
    });
  });
}
export default function Signin() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const [search] = useSearchParams();
  const [create, setCreate] = useState(false);
  const [name, setName] = useState('');
  const task = useTask();
  const back = safeReturn(search.get('returnTo'));
  return (
    <div className="mx-auto max-w-sm py-8 sm:py-16">
      <Page title={t(create ? 'signup' : 'signinTitle')} narrow>
        <p className="leading-relaxed text-muted-foreground">{t('signinDescription')}</p>
        <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
        <Panel>
          <div className="flex min-w-0 flex-col gap-6">
            {create && (
              <InputField
                required
                label={t('name')}
                value={name}
                onChange={(event) => setName(event.target.value)}
                autoComplete="name"
                maxLength={200}
              />
            )}
            <Button
              loading={task.busy}
              disabled={create && !name.trim()}
              onClick={() =>
                task.run(async () => {
                  const auth = create ? await registerPasskey(name) : await authenticate();
                  window.location.assign(
                    back === '/' && !auth.encrypted ? '/account?encryption=unavailable' : back,
                  );
                })
              }
              variant="default"
              size="lg"
            >
              {<FingerprintIcon />}
              {t(create ? 'passkeyCreate' : 'passkeySignin')}
            </Button>
            <Button onClick={() => setCreate(!create)} variant="ghost">
              {t(create ? 'signin' : 'signup')}
            </Button>
            {data.features.email && (
              <>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <Separator className="flex-1" />
                  <span>{t('or')}</span>
                  <Separator className="flex-1" />
                </div>
                <Form method="post">
                  <div className="flex min-w-0 flex-col gap-4">
                    <input type="hidden" name="returnTo" value={back} />
                    <InputField
                      required
                      type="email"
                      name="email"
                      label={t('email')}
                      autoComplete="email"
                    />
                    {result && 'email' in result && (
                      <Notice tone={'success'}>{t('emailSent', { email: result.email })}</Notice>
                    )}
                    <Button type="submit" variant="outline">
                      {t('sendLink')}
                    </Button>
                  </div>
                </Form>
              </>
            )}
          </div>
        </Panel>
      </Page>
    </div>
  );
}
