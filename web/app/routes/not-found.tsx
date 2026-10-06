import { Button } from '../components/ui/button';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Page } from '../components';
export default function NotFound() {
  const { t } = useTranslation();
  return (
    <Page title={t('notFound')}>
      <Button variant="ghost" asChild>
        <Link to="/">{t('goHome')}</Link>
      </Button>
    </Page>
  );
}
