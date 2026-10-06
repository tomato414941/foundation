import { Link as RouterLink } from 'react-router';
import {
  Link,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { ResourceView } from '../../shared/contracts';
import { Bytes, DateText, Empty, State } from './components';
import { resourcePath, sectionFor } from './navigation';
export function ResourceTable({
  items,
  kinds = false,
  search = false,
}: {
  items: ResourceView[];
  kinds?: boolean;
  search?: boolean;
}) {
  const { t } = useTranslation();
  if (!items.length) return <Empty search={search} />;
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>{t('name')}</TableCell>
            <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
              {t(kinds ? 'kind' : 'status')}
            </TableCell>
            <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{t('updated')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {items.map((item) => (
            <TableRow key={item.id} hover>
              <TableCell>
                <Stack spacing={0.5}>
                  <Link
                    component={RouterLink}
                    to={resourcePath(item)}
                    underline="hover"
                    sx={{ overflowWrap: 'anywhere' }}
                  >
                    {item.name}
                  </Link>
                  {item.kind === 'connection' && (
                    <>
                      <Typography variant="body2" color="text.secondary">
                        {item.data.methodName}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {item.data.account || t('accountUnverified')}
                        {item.data.account && !item.data.accountVerified && ' · ' + t('accountUnverified')}
                      </Typography>
                    </>
                  )}
                  <Stack direction="row" sx={{ display: { sm: 'none' } }}>
                    {'state' in item.data && <State value={item.data.state} />}
                    {item.kind === 'object' && <Bytes value={item.data.size} />}
                  </Stack>
                </Stack>
              </TableCell>
              <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                {kinds ? (
                  t(sectionFor(item.kind))
                ) : 'state' in item.data ? (
                  <State value={item.data.state} />
                ) : item.kind === 'object' ? (
                  <Bytes value={item.data.size} />
                ) : item.kind === 'secret' ? (
                  <Bytes value={item.data.bytes} />
                ) : (
                  '—'
                )}
              </TableCell>
              <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                <DateText value={item.updatedAt} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
