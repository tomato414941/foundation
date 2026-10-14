import { Form } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { z } from 'zod';
import type { FunctionExecutionSettings, ResourceView } from '../../shared/contracts';
import { Button } from './components/ui/button';
import { DateText, Detail, Panel } from './components';
import { EnvironmentChoice } from './environments';
import { FunctionAccessFields } from './function-access';

export function FunctionSettings({ settings, environments, functionVersion, canUpdate, busy }: {
  settings: z.infer<typeof FunctionExecutionSettings>; environments: ResourceView[];
  functionVersion: number; canUpdate: boolean; busy: boolean;
}) {
  const { t } = useTranslation();
  return <Panel title={t('functionExecutionSettings')}>
    <Detail label={t('status')}>{t('functionSettingsState.' + settings.state)}</Detail>
    <Detail label={t('executionDestination')}>
      {environments.find(item => item.id === settings.environmentId)?.name ?? (settings.environmentId ? t('functionEnvironmentConfigured') : t('none'))}
    </Detail>
    {settings.environmentId && <Detail label={t('functionInputAccess')}>
      {settings.inputAccess.expiresAt ? <DateText value={settings.inputAccess.expiresAt} /> : t('functionInputContinuous')}
    </Detail>}
    {canUpdate && <details open={settings.state !== 'configured'}>
      <summary className="cursor-pointer py-3 text-sm font-medium">{t('functionConfigure')}</summary>
      <Form method="post" className="grid gap-5 pt-3" key={settings.version}>
        <input type="hidden" name="functionVersion" value={functionVersion} />
        <input type="hidden" name="settingsVersion" value={settings.version} />
        <EnvironmentChoice items={environments} selected={environments.some(item => item.id === settings.environmentId) ? [settings.environmentId!] : []} />
        <FunctionAccessFields access={settings.inputAccess} />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" name="intent" value="functionConfigure" loading={busy} disabled={!environments.length}>
            {t('functionApproveSettings')}
          </Button>
          {settings.environmentId && <Button type="submit" name="intent" value="functionUnconfigure" variant="outline" formNoValidate loading={busy}>
            {t('functionUnconfigure')}
          </Button>}
        </div>
      </Form>
    </details>}
  </Panel>;
}
