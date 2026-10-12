import { useTranslation } from 'react-i18next';
import { ConnectionSettings as Settings } from '../../shared/connections';
import { Detail } from './components';
import { serviceLabels } from './service-labels';

export function ConnectionSettings({ methodId, settings }: { methodId: string; settings: unknown }) {
  const { i18n } = useTranslation(), parsed = Settings.safeParse(settings), service = methodId.split(':')[0];
  if (!parsed.success) return null;
  return parsed.data.map(setting => <Detail key={setting.name}
    label={i18n.language === 'ja' ? serviceLabels[`${service}.oauth.${setting.name}.label`] ??
      serviceLabels[`${service}.token.${setting.name}.label`] ?? setting.label : setting.label}>
    {setting.value}
  </Detail>);
}
