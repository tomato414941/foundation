import { Button } from '../components/ui/button';
import { SelectItem } from '../components/ui/select';
import { InputField, TextareaField, SelectField } from '../form-fields';
import { Notice } from '../components';
import { useState } from 'react';
import { Form, Link, useActionData, useNavigate, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/credential-new';
import { actionResult, api, formText } from '../api';
import { issueKey, registerPasskey } from '../keys';
import { Principal } from '../../../shared/contracts';
import { Copy, ErrorNotice, Page, Panel, SaveBar, useTask } from '../components';
import { useWorkspace } from './workspace';
import i18n from '../i18n';
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    if (formText(form, 'kind') === 'email')
      return api<{
        email: string;
      }>('/auth/email', {
        method: 'POST',
        body: {
          email: formText(form, 'email'),
          principalId: params.owner,
          returnTo: `/p/${params.owner}/settings/credentials`,
          locale: i18n.language === 'en' ? 'en' : 'ja',
        },
      });
    const principal = await api('/principals/' + params.owner, {}, Principal);
    return issueKey(
      principal,
      formText(form, 'name'),
      formText(form, 'expiresAt') ? new Date(formText(form, 'expiresAt')).toISOString() : null,
    );
  });
}
export default function CredentialNew() {
  const { t } = useTranslation();
  const { principal, session } = useWorkspace();
  const result = useActionData<typeof clientAction>();
  const [kind, setKind] = useState('passkey');
  const [name, setName] = useState('');
  const task = useTask();
  const navigate = useNavigate();
  const revalidator = useRevalidator();
  const back = `/p/${principal.id}/settings/credentials`;
  return (
    <Page title={t('add')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      {result && 'token' in result ? (
        <Panel title={t('apiKey')}>
          <Notice tone={'info'}>{t('keyOnce')}</Notice>
          <TextareaField label={t('apiKey')} value={result.token} readOnly={true} />
          <Copy value={result.token} />
          <Button variant="ghost" asChild>
            <Link to={back}>{t('close')}</Link>
          </Button>
        </Panel>
      ) : (
        <Form
          method="post"
          onSubmit={(event) => {
            if (kind === 'passkey') {
              event.preventDefault();
              void task.run(async () => {
                await registerPasskey(name, principal);
                await revalidator.revalidate();
                await navigate(back);
              });
            }
          }}
        >
          <div className="flex min-w-0 flex-col gap-6">
            <SelectField
              name="kind"
              label={t('kind')}
              value={kind}
              onValueChange={(value) => setKind(value)}
            >
              <SelectItem value={'passkey'}>{t('addPasskey')}</SelectItem>
              {session.features.email && <SelectItem value={'email'}>{t('email')}</SelectItem>}
              <SelectItem value={'key'}>{t('apiKey')}</SelectItem>
            </SelectField>
            {kind === 'email' ? (
              <InputField name="email" type="email" label={t('email')} required autoComplete="email" />
            ) : (
              <InputField
                name="name"
                label={t('name')}
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
              />
            )}
            {kind === 'key' && (
              <InputField
                name="expiresAt"
                type="datetime-local"
                label={t('expires')}
                hint={t('noExpiry')}
              />
            )}
            {result && 'email' in result && (
              <Notice tone={'success'}>{t('emailSent', { email: result.email })}</Notice>
            )}
            <SaveBar back={back} label={kind === 'email' ? 'sendLink' : 'add'} busy={task.busy} />
          </div>
        </Form>
      )}
    </Page>
  );
}
