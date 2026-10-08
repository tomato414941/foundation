import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { setNonce } from 'get-nonce';
import { cn } from 'cn';
import {
  BookOpen,
  Code2,
  Folder,
  House,
  Inbox,
  KeyRound,
  Link2,
  LogOut,
  Menu,
  Settings,
  Terminal,
  Users,
  CircleUserRound,
  X,
} from 'lucide-react';
import {
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
  Link,
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
import { clearKeys, migrateUnlockedContent } from './keys';
import { Busy, ErrorNotice, Page, useTask } from './components';
import { Button } from './components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Sheet, SheetClose, SheetContent, SheetTitle } from './components/ui/sheet';
import { TooltipProvider } from './components/ui/tooltip';
import { Label } from './components/ui/label';
import './app.css';

export const meta: Route.MetaFunction = () => [
  { title: 'Foundation' },
  { name: 'description', content: 'Manage service connections and secrets.' },
  { name: 'theme-color', content: '#0a0a0a' },
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
  if (nonce) setNonce(nonce);
  return (
    <html lang="ja" className="dark">
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
        <TooltipProvider delayDuration={300}>{children}</TooltipProvider>
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
  const migration = useTask();
  const principal = data.principals.find((item) => item.id === owner) ?? data.principal;
  const prefix = '/p/' + (owner ?? data.principal?.id);
  const authenticated = !!data.principal && !data.requestId;
  useEffect(() => {
    if (authenticated) void migration.run(() => migrateUnlockedContent(data.principal!.id));
  }, [authenticated, data.principal?.id]);
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

  const navigationGroups = [
    [
      ['home', prefix, House],
      ['services', prefix + '/services', Link2],
      ['secrets', prefix + '/secrets', KeyRound],
      ['objects', prefix + '/objects', Folder],
      ['environments', prefix + '/environments', Terminal],
      ['functions', prefix + '/functions', Code2],
      ['principals', prefix + '/principals', Users],
      ['runs', prefix + '/runs', Terminal],
    ],
    [
      ['requests', '/requests', Inbox],
      ['shared', '/shared', Users],
      ['settings', prefix + '/settings/general', Settings],
      ['account', '/account', CircleUserRound],
    ],
  ] as const;
  const brand = (
    <Link to="/" className="inline-flex items-center gap-2.5 font-semibold tracking-tight">
      <img src="/logo.svg" alt="" className="size-6" />
      <span>Foundation</span>
    </Link>
  );
  const nav = (mobile: boolean) => (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-14 shrink-0 items-center px-5">{brand}</div>
      <div className="grid gap-2 px-3 pb-4 pt-2">
        <Label
          htmlFor={mobile ? 'mobile-workspace' : 'workspace'}
          className="px-1 text-xs font-normal text-muted-foreground"
        >
          {t('workspace')}
        </Label>
        <Select
          value={data.principals.some((item) => item.id === principal?.id) ? principal?.id : ''}
          onValueChange={(value) => void navigate('/p/' + value)}
        >
          <SelectTrigger
            id={mobile ? 'mobile-workspace' : 'workspace'}
            className="h-9 w-full bg-background/50"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent position="popper" align="start">
            {data.principals.map((item) => (
              <SelectItem key={item.id} value={item.id}>
                {item.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <nav className="min-h-0 flex-1 overflow-y-auto px-2" aria-label={t('menu')}>
        {navigationGroups.map((group, index) => (
          <ul key={index} className={cn('space-y-1 py-3', index > 0 && 'mt-2 border-t')}>
            {group.map(([label, to, Icon]) => {
              const selected =
                label === 'home'
                  ? location.pathname === to
                  : label === 'settings'
                    ? location.pathname.startsWith(prefix + '/settings')
                    : location.pathname.startsWith(to);
              return (
                <li key={label}>
                  <Button
                    asChild
                    variant="ghost"
                    className={cn(
                      'h-9 w-full justify-start gap-3 px-3 font-normal text-muted-foreground',
                      selected && 'bg-accent/70 font-medium text-foreground',
                    )}
                  >
                    <Link to={to} aria-current={selected ? 'page' : undefined}>
                      <Icon className="size-4" aria-hidden="true" />
                      {t(label)}
                    </Link>
                  </Button>
                </li>
              );
            })}
          </ul>
        ))}
      </nav>
      <div className="border-t p-3">
        <Button
          asChild
          variant="ghost"
          className="w-full justify-start gap-3 text-xs font-normal text-muted-foreground"
        >
          <a href="/api/docs" target="_blank" rel="noopener noreferrer">
            <BookOpen className="size-4" />
            {t('apiDocs')}
          </a>
        </Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-dvh">
      {authenticated && (
        <>
          <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r bg-card/50 md:block">
            {nav(false)}
          </aside>
          <Sheet open={drawer} onOpenChange={setDrawer}>
            <SheetContent
              side="left"
              showCloseButton={false}
              aria-describedby={undefined}
              className="w-72 gap-0 p-0 data-[side=left]:w-72"
            >
              <SheetTitle className="sr-only">{t('menu')}</SheetTitle>
              {nav(true)}
              <SheetClose asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="absolute right-3 top-3"
                  aria-label={t('close')}
                >
                  <X className="size-4" />
                </Button>
              </SheetClose>
            </SheetContent>
          </Sheet>
        </>
      )}
      <div className={authenticated ? 'md:pl-60' : ''}>
        <header className="sticky top-0 z-20 border-b bg-background/95 backdrop-blur-sm">
          <div className="flex h-14 items-center gap-2 px-4 sm:px-6 lg:px-8">
            {authenticated && (
              <Button
                variant="ghost"
                size="icon"
                className="-ml-2 md:hidden"
                onClick={() => setDrawer(true)}
                aria-label={t('menu')}
              >
                <Menu className="size-4" />
              </Button>
            )}
            <div className="min-w-0 flex-1 truncate text-sm font-medium">
              {authenticated ? principal?.name : brand}
            </div>
            <Select
              value={i18n.language === 'en' ? 'en' : 'ja'}
              onValueChange={(value) => {
                void i18n.changeLanguage(value);
                localStorage.setItem('foundation.language', value);
              }}
            >
              <SelectTrigger
                size="sm"
                aria-label={t('language')}
                className="w-24 border-transparent bg-transparent text-xs shadow-none dark:bg-transparent"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper" align="end">
                <SelectItem value="ja">日本語</SelectItem>
                <SelectItem value="en">English</SelectItem>
              </SelectContent>
            </Select>
            {data.principal && (
              <Button
                variant="ghost"
                size="sm"
                loading={task.busy}
                aria-label={t('signout')}
                onClick={() =>
                  task.run(async () => {
                    await api('/auth/signout', { method: 'POST', body: {} });
                    await clearKeys();
                    window.location.assign('/signin');
                  })
                }
              >
                <LogOut className="size-3.5" aria-hidden="true" />
                <span className="hidden sm:inline">{t('signout')}</span>
              </Button>
            )}
          </div>
          {navigation.state !== 'idle' && (
            <div
              role="progressbar"
              aria-label={t('loading')}
              className="absolute inset-x-0 bottom-0 h-px animate-pulse bg-primary"
            />
          )}
        </header>
        <main tabIndex={-1} className="min-w-0 px-4 py-6 outline-none sm:px-6 lg:px-8 lg:py-8">
          <ErrorNotice error={task.error ?? migration.error} />
          <Outlet />
        </main>
      </div>
    </div>
  );
}
export function ErrorBoundary() {
  const error = useRouteError();
  const { t } = useTranslation();
  return (
    <main className="px-6 py-12">
      <Page title={isRouteErrorResponse(error) && error.status === 404 ? t('notFound') : t('failure')}>
        <ErrorNotice error={isRouteErrorResponse(error) ? null : errorCode(error)} />
        <div className="flex items-center gap-2">
          <Button asChild>
            <Link to="/">{t('goHome')}</Link>
          </Button>
          <Button variant="outline" onClick={() => window.location.reload()}>
            {t('refresh')}
          </Button>
        </div>
      </Page>
    </main>
  );
}
