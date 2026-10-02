import { createI18n } from './i18n.js';

const japanese = createI18n('ja').t;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
export const pages = { '/': 'nav.foundation', '/services': 'nav.services', '/secrets': 'nav.secrets', '/objects': 'nav.objects', '/principals': 'nav.principals', '/functions': 'nav.functions', '/account': 'nav.account' };
export const brand = (t = japanese) => `<a class="brand" href="/" aria-label="${esc(t('brand.home'))}"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 48 48" fill="currentColor"><path d="M11 37V11H37M11 24H24" fill="none" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" opacity=".6"/><circle cx="37" cy="24" r="3" opacity=".3"/><circle cx="24" cy="37" r="3" opacity=".3"/><circle cx="37" cy="37" r="3" opacity=".3"/><circle cx="11" cy="11" r="4"/><circle cx="24" cy="11" r="4"/><circle cx="37" cy="11" r="4"/><circle cx="11" cy="24" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="11" cy="37" r="4"/></svg></span>Foundation</a>`;

export const loading = (t = japanese) => `<div class="content-loading" role="status" aria-label="${esc(t('common.loading'))}"><span></span><span></span><span></span></div>`;
export const pageTitle = (path, t = japanese) => path === '/' || !Object.hasOwn(pages, path) ? 'Foundation' : t(pages[path]) + ' · Foundation';

export function languagePicker(t = japanese, locale = t('locale')) {
  return `<label class="language-picker"><span class="sr-only">${esc(t('language.label'))}</span><select data-action="change-language" aria-label="${esc(t('language.label'))}"><option value="ja" lang="ja"${locale === 'ja' ? ' selected' : ''}>日本語</option><option value="en" lang="en"${locale === 'en' ? ' selected' : ''}>English</option></select></label>`;
}

// Only the public frame: session validation and all private data still come from the API.
export function workspaceView(path, { pending = false, t = japanese, locale = t('locale') } = {}) {
  const link = (href, label) => `<a href="${href}"${href === path ? ' aria-current="page"' : ''}>${esc(label)}</a>`;
  const nav = `<nav class="page-nav" aria-label="${esc(t('nav.label'))}">${Object.entries(pages).filter(([href]) => href !== '/' && href !== '/account').map(([href, key]) => link(href, t(key))).join('')}</nav>`;
  return `<div class="workspace"><header class="topbar">${brand(t)}${nav}<div class="user-menu">${languagePicker(t, locale)}${link('/account', t('nav.account'))}<button class="text-button" data-action="signout"${pending ? ' disabled' : ''}>${esc(t('nav.signout'))}</button></div></header><main tabindex="-1"${pending ? ' aria-busy="true"' : ''}>${pending ? `<header class="page-heading"><h1>${esc(t(Object.hasOwn(pages, path) ? pages[path] : 'nav.foundation'))}</h1></header>${loading(t)}` : ''}</main></div>`;
}

export function pendingView(path, { t = japanese, locale = t('locale') } = {}) {
  return `<div class="workspace signin-shell"><header class="topbar">${brand(t)}${languagePicker(t, locale)}</header><main class="signin-main" aria-busy="true"><h1>${esc(t(Object.hasOwn(pages, path) ? pages[path] : 'nav.foundation'))}</h1>${loading(t)}</main></div>`;
}
