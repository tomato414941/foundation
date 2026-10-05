import { Button } from '@mui/material';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Page } from '../components';
export default function NotFound() {
  const { t } = useTranslation();
  return (
    <Page title={t('notFound')}>
      <Button component={Link} to="/">
        {t('goHome')}
      </Button>
    </Page>
  );
}
