import { InputField } from '../form-fields';
import { Form, redirect, useActionData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/principal-new';
import { Principal } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { ErrorNotice, Page, SaveBar } from '../components';
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const principal = await api(
      '/principals',
      { method: 'POST', body: { name: formText(form, 'name'), ownerId: params.owner } },
      Principal,
    );
    return redirect('/p/' + principal.id);
  });
}
export default function PrincipalNew() {
  const { t } = useTranslation();
  const result = useActionData<typeof clientAction>();
  return (
    <Page title={t('createPrincipal')} narrow>
      <p className="leading-relaxed text-muted-foreground">{t('principalHelp')}</p>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Form method="post">
        <div className="flex min-w-0 flex-col gap-6">
          <InputField label={t('name')} name="name" required autoFocus />
          <SaveBar back=".." label="create" />
        </div>
      </Form>
    </Page>
  );
}
