import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { RecipientVerification } from '../../shared/client';

export function RecipientVerificationLinks({ recipients }: { recipients: RecipientVerification[] }) {
  const { t } = useTranslation();
  const unique = [...new Map(recipients.map(recipient => [recipient.id, recipient])).values()];
  if (!unique.length) return null;
  return <ul className="mt-2 space-y-2">
    {unique.map(recipient => <li key={recipient.id} className="wrap-anywhere">
      <Link className="underline underline-offset-4" to={'/account/trust?principal=' + recipient.id} target="_blank" rel="noopener noreferrer">
        {t('verifyRecipient', { name: recipient.name })}
      </Link>
      {recipient.code === 'identity_changed' && <p>{t('errors.identity_changed')}</p>}
    </li>)}
  </ul>;
}
