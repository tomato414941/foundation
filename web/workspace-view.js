import { createI18n } from './i18n.js';

const japanese = createI18n('ja').t;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
export const pages = { '/': 'nav.foundation', '/services': 'nav.services', '/secrets': 'nav.secrets', '/objects': 'nav.objects', '/environments': 'nav.environments', '/principals': 'nav.principals', '/functions': 'nav.functions', '/account': 'nav.account' };
// The menu, with what is used most first: the things one holds, then who may reach them and what may be done. What
// one holds goes from the light to the heavy: connections and secrets are small values and unmetered; objects and
// environments are metered.
export const menu = [['/services', '/secrets', '/objects', '/environments'], ['/principals', '/functions']];
export const brand = (t = japanese) => `<a class="brand" href="/" aria-label="${esc(t('brand.home'))}"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 48 48" fill="currentColor"><path d="M11 37V11H37M11 24H24" fill="none" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" opacity=".6"/><circle cx="37" cy="24" r="3" opacity=".3"/><circle cx="24" cy="37" r="3" opacity=".3"/><circle cx="37" cy="37" r="3" opacity=".3"/><circle cx="11" cy="11" r="4"/><circle cx="24" cy="11" r="4"/><circle cx="37" cy="11" r="4"/><circle cx="11" cy="24" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="11" cy="37" r="4"/></svg></span>Foundation</a>`;

export const loading = (t = japanese) => `<div class="content-loading" role="status" aria-label="${esc(t('common.loading'))}"><span></span><span></span><span></span></div>`;
export const pageTitle = (path, t = japanese) => path === '/' || !Object.hasOwn(pages, path) ? 'Foundation' : t(pages[path]) + ' · Foundation';

export function languagePicker(t = japanese, locale = t('locale')) {
  return `<label class="language-picker"><span class="sr-only">${esc(t('language.label'))}</span><select data-action="change-language" aria-label="${esc(t('language.label'))}"><option value="ja" lang="ja"${locale === 'ja' ? ' selected' : ''}>日本語</option><option value="en" lang="en"${locale === 'en' ? ' selected' : ''}>English</option></select></label>`;
}

// Only the public frame: session validation and all private data still come from the API.
export function workspaceView(path, { pending = false, t = japanese } = {}) {
  const link = (href, label) => `<a href="${href}"${href === path ? ' aria-current="page"' : ''}>${esc(label)}</a>`;
  const nav = `<nav class="page-nav" aria-label="${esc(t('nav.label'))}">${menu.map(group => `<div class="nav-group">${group.map(href => link(href, t(pages[href]))).join('')}</div>`).join('')}</nav>`;
  // Beside the page where there is room for it; behind a button where there is not.
  const toggle = `<button class="menu-toggle icon-button" type="button" data-action="toggle-menu" aria-expanded="false" aria-controls="site-menu" aria-label="${esc(t('nav.menu'))}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>`;
  return `<div class="workspace with-menu"><header class="topbar">${brand(t)}${toggle}<div class="site-menu" id="site-menu">${nav}<div class="user-menu">${link('/account', t('nav.account'))}<button class="text-button" data-action="signout"${pending ? ' disabled' : ''}>${esc(t('nav.signout'))}</button></div></div></header><main tabindex="-1"${pending ? ' aria-busy="true"' : ''}>${pending ? `<header class="page-heading"><h1>${esc(t(Object.hasOwn(pages, path) ? pages[path] : 'nav.foundation'))}</h1></header>${loading(t)}` : ''}</main></div>`;
}

export function pendingView(path, { t = japanese } = {}) {
  return `<div class="workspace signin-shell"><header class="topbar">${brand(t)}</header><main class="signin-main" aria-busy="true"><h1>${esc(t(Object.hasOwn(pages, path) ? pages[path] : 'nav.foundation'))}</h1>${loading(t)}</main></div>`;
}
