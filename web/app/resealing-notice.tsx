import { useTranslation } from 'react-i18next';
import { Notice } from './components';
import { useResealing } from './keys';

// The items this browser could not yet seal again for who may now open them, and why. They are tried again later.
export function ResealingNotice({ principalId }: { principalId?: string }) {
  const { t } = useTranslation(), outcome = useResealing(principalId);
  if (!outcome?.failed.length) return null;
  return <Notice tone="warning">
    <p>{t('resealingPending')}</p>
    <ul className="mt-2 list-disc space-y-1 pl-5">
      {outcome.failed.map(item => <li key={item.id} className="wrap-anywhere">
        {t('resealingItem', { name: item.name ?? t('result'), reason: t('errors.' + item.code, { defaultValue: t('failure') }) })}
      </li>)}
    </ul>
  </Notice>;
}
