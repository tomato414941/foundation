import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import {
  AppBar,
  Box,
  Button,
  Container,
  CssBaseline,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputLabel,
  LinearProgress,
  Link,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Select,
  Stack,
  ThemeProvider,
  Toolbar,
  Typography,
  createTheme,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import HomeIcon from '@mui/icons-material/HomeOutlined';
import LinkIcon from '@mui/icons-material/Link';
import KeyIcon from '@mui/icons-material/KeyOutlined';
import FolderIcon from '@mui/icons-material/FolderOutlined';
import TerminalIcon from '@mui/icons-material/Terminal';
import CodeIcon from '@mui/icons-material/Code';
import PeopleIcon from '@mui/icons-material/PeopleOutlined';
import InboxIcon from '@mui/icons-material/InboxOutlined';
import SettingsIcon from '@mui/icons-material/SettingsOutlined';
import {
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
  Link as RouterLink,
  isRouteErrorResponse,
  useLoaderData,
  useLocation,
  useNavigate,
  useNavigation,
  useParams,
  useRouteError,
} from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/root';
import i18n from './i18n';
import { api, errorCode, session } from './api';
import { clearKeys } from './keys';
import { Busy, ErrorNotice, Page, useTask } from './components';

const theme = createTheme({
  typography: { fontFamily: 'Roboto, "Noto Sans JP", "Helvetica Neue", Arial, sans-serif' },
});
export const meta: Route.MetaFunction = () => [
  { title: 'Foundation' },
  { name: 'description', content: 'Manage service connections and secrets.' },
];
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  return session(request);
}
clientLoader.hydrate = true as const;
export function Layout({ children }: { children: ReactNode }) {
  const nonce =
    typeof document === 'undefined'
      ? '__FOUNDATION_NONCE__'
      : document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;
  const cache = useMemo(() => createCache({ key: 'mui', nonce }), [nonce]);
  return (
    <html lang="ja">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="csp-nonce" content={nonce} />
        <link rel="icon" href="/favicon.png" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <Meta />
        <Links />
      </head>
      <body>
        <CacheProvider value={cache}>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            {children}
          </ThemeProvider>
        </CacheProvider>
        <ScrollRestoration nonce={nonce} />
        <Scripts nonce={nonce} />
      </body>
    </html>
  );
}
export function HydrateFallback() {
  return <Busy />;
}
export default function App() {
  const data = useLoaderData<typeof clientLoader>();
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const navigation = useNavigation();
  const { owner } = useParams();
  const [drawer, setDrawer] = useState(false);
  const task = useTask();
  const principal = data.principals.find((item) => item.id === owner) ?? data.principal;
  const prefix = '/p/' + (owner ?? data.principal?.id);
  const authenticated = !!data.principal && !data.requestId;
  useEffect(() => {
    const language = localStorage.getItem('foundation.language');
    if (language === 'en' || language === 'ja') void i18n.changeLanguage(language);
  }, []);
  useEffect(() => {
    document.documentElement.lang = i18n.language;
  }, [t]);
  useEffect(() => {
    setDrawer(false);
    document.querySelector<HTMLElement>('main')?.focus({ preventScroll: true });
  }, [location.pathname]);
  const nav = (
    <>
      <Toolbar>
        <Box component="img" src="/logo.svg" alt="" sx={{ width: 26, height: 26, mr: 1.5 }} />
        <Typography
          variant="h6"
          component={RouterLink}
          to="/"
          sx={{ color: 'inherit', textDecoration: 'none' }}
        >
          Foundation
        </Typography>
      </Toolbar>
      <Box sx={{ px: 2, pb: 2 }}>
        <FormControl fullWidth size="small">
          <InputLabel id="workspace-label">{t('workspace')}</InputLabel>
          <Select
            labelId="workspace-label"
            label={t('workspace')}
            value={data.principals.some((item) => item.id === principal?.id) ? principal?.id : ''}
            onChange={(event) => void navigate('/p/' + event.target.value)}
          >
            {data.principals.map((item) => (
              <MenuItem key={item.id} value={item.id}>
                {item.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>
      <Divider />
      <List>
        {(
          [
            ['home', prefix, HomeIcon],
            ['services', prefix + '/services', LinkIcon],
            ['secrets', prefix + '/secrets', KeyIcon],
            ['objects', prefix + '/objects', FolderIcon],
            ['environments', prefix + '/environments', TerminalIcon],
            ['functions', prefix + '/functions', CodeIcon],
            ['principals', prefix + '/principals', PeopleIcon],
            ['runs', prefix + '/runs', TerminalIcon],
          ] as const
        ).map(([label, to, Icon]) => (
          <ListItemButton
            component={RouterLink}
            to={to}
            key={label}
            selected={label === 'home' ? location.pathname === to : location.pathname.startsWith(to)}
          >
            <ListItemIcon>
              <Icon />
            </ListItemIcon>
            <ListItemText primary={t(label)} />
          </ListItemButton>
        ))}
      </List>
      <Divider />
      <List>
        {(
          [
            ['requests', '/requests', InboxIcon],
            ['shared', '/shared', PeopleIcon],
            ['settings', prefix + '/settings/general', SettingsIcon],
            ['account', '/account', PeopleIcon],
          ] as const
        ).map(([label, to, Icon]) => (
          <ListItemButton
            component={RouterLink}
            key={label}
            to={to}
            selected={location.pathname.startsWith(to)}
          >
            <ListItemIcon>
              <Icon />
            </ListItemIcon>
            <ListItemText primary={t(label)} />
          </ListItemButton>
        ))}
      </List>
      <Box sx={{ px: 2, py: 2 }}>
        <Link href="/api/docs" target="_blank" rel="noopener noreferrer">
          {t('apiDocs')}
        </Link>
      </Box>
    </>
  );
  return (
    <Box sx={{ display: 'flex', minHeight: '100dvh' }}>
      {authenticated && (
        <>
          <Drawer
            variant="permanent"
            sx={{
              display: { xs: 'none', md: 'block' },
              width: 248,
              flexShrink: 0,
              '& .MuiDrawer-paper': { width: 248, boxSizing: 'border-box' },
            }}
          >
            {nav}
          </Drawer>
          <Drawer
            open={drawer}
            onClose={() => setDrawer(false)}
            sx={{ display: { md: 'none' }, '& .MuiDrawer-paper': { width: 280 } }}
          >
            {nav}
          </Drawer>
        </>
      )}
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        <AppBar
          position="sticky"
          color="default"
          elevation={0}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Toolbar sx={{ gap: 1 }}>
            {authenticated && (
              <IconButton
                edge="start"
                onClick={() => setDrawer(true)}
                aria-label={t('menu')}
                sx={{ display: { md: 'none' } }}
              >
                <MenuIcon />
              </IconButton>
            )}
            <Typography
              sx={{ flexGrow: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
            >
              {authenticated ? principal?.name : 'Foundation'}
            </Typography>
            <Select
              size="small"
              value={i18n.language === 'en' ? 'en' : 'ja'}
              inputProps={{ 'aria-label': t('language') }}
              onChange={(event) => {
                void i18n.changeLanguage(event.target.value);
                localStorage.setItem('foundation.language', event.target.value);
              }}
            >
              <MenuItem value="ja">日本語</MenuItem>
              <MenuItem value="en">English</MenuItem>
            </Select>
            {data.principal && (
              <Button
                size="small"
                loading={task.busy}
                onClick={() =>
                  task.run(async () => {
                    await api('/auth/signout', { method: 'POST', body: {} });
                    await clearKeys();
                    window.location.assign('/signin');
                  })
                }
              >
                {t('signout')}
              </Button>
            )}
          </Toolbar>
          {navigation.state !== 'idle' && (
            <LinearProgress sx={{ position: 'absolute', bottom: 0, width: '100%' }} />
          )}
        </AppBar>
        <Container
          component="main"
          tabIndex={-1}
          maxWidth={false}
          sx={{ p: { xs: 2, sm: 3, lg: 4 }, outline: 'none' }}
        >
          <ErrorNotice error={task.error} />
          <Outlet />
        </Container>
      </Box>
    </Box>
  );
}
export function ErrorBoundary() {
  const error = useRouteError();
  const { t } = useTranslation();
  return (
    <Container sx={{ py: 6 }}>
      <Page title={isRouteErrorResponse(error) && error.status === 404 ? t('notFound') : t('failure')}>
        <ErrorNotice error={isRouteErrorResponse(error) ? null : errorCode(error)} />
        <Stack direction="row" spacing={2}>
          <Button component={RouterLink} to="/">
            {t('goHome')}
          </Button>
          <Button onClick={() => window.location.reload()}>{t('refresh')}</Button>
        </Stack>
      </Page>
    </Container>
  );
}
