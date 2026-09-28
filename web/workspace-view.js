export const pages = { '/': 'Foundation', '/services': 'サービス', '/secrets': 'シークレット', '/objects': 'オブジェクト', '/principals': 'アクセス管理', '/functions': 'ファンクション', '/account': 'アカウント' };
export const brand = '<a class="brand" href="/" aria-label="Foundation ホーム"><span class="brand-mark" aria-hidden="true">F</span>Foundation</a>';
export const loading = '<div class="content-loading" role="status" aria-label="読み込み中"><span></span><span></span><span></span></div>';
export const pageTitle = path => path === '/' || !Object.hasOwn(pages, path) ? 'Foundation' : pages[path] + ' · Foundation';

// Only the public frame: session validation and all private data still come from the API.
export function workspaceView(path, { pending = false } = {}) {
  const link = (href, label) => `<a href="${href}"${href === path ? ' aria-current="page"' : ''}>${label}</a>`;
  const nav = `<nav class="page-nav">${Object.entries(pages).filter(([href]) => href !== '/' && href !== '/account').map(([href, label]) => link(href, label)).join('')}</nav>`;
  return `<div class="workspace"><header class="topbar">${brand}${nav}<div class="user-menu">${link('/account', 'アカウント')}<button class="text-button" data-action="logout"${pending ? ' disabled' : ''}>ログアウト</button></div></header><main tabindex="-1"${pending ? ' aria-busy="true"' : ''}>${pending ? `<header class="page-heading"><h1>${pages[path] || 'Foundation'}</h1></header>${loading}` : ''}</main></div>`;
}

export function pendingView(path) {
  return `<div class="workspace login-shell"><header class="topbar">${brand}</header><main class="login-main" aria-busy="true"><h1>${pages[path] || 'Foundation'}</h1>${loading}</main></div>`;
}
