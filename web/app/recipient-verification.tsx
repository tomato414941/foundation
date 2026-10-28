import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { RecipientVerification } from '../../shared/client';
import { useRecipientAccess } from './keys';
import { Notice } from './components';

export function RecipientAccessNotice({ principalId, id }: { principalId?: string; id: string }) {
  const access = useRecipientAccess(principalId, id), { t } = useTranslation();
  if (!access?.excluded.length) return null;
  return <Notice tone="warning">
    <p>{t(access.operation === 'transfer' ? 'recipientExclusionsTransfer' : 'recipientExclusionsSaved')}</p>
    {access.operation === 'transfer' ? <ul className="mt-2 space-y-2">
      {access.excluded.map(recipient => <li key={recipient.id} className="wrap-anywhere">
        <span>{recipient.name}</span><p>{t('recipientExclusionReasons.' + recipient.code)}</p>
      </li>)}
    </ul> : <RecipientVerificationLinks recipients={access.excluded} />}
  </Notice>;
}

export function RecipientVerificationLinks({ recipients }: { recipients: RecipientVerification[] }) {
  const { t } = useTranslation();
  const unique = [...new Map(recipients.map(recipient => [recipient.id, recipient])).values()];
  if (!unique.length) return null;
  return <ul className="mt-2 space-y-2">
    {unique.map(recipient => <li key={recipient.id} className="wrap-anywhere">
      <Link className="underline underline-offset-4" to={'/account/trust?principal=' + recipient.id} target="_blank" rel="noopener noreferrer">
        {t('verifyRecipient', { name: recipient.name })}
      </Link>
      <p>{t('recipientExclusionReasons.' + recipient.code)}</p>
    </li>)}
  </ul>;
}
