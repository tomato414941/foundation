const kinds = {
  actor: { done: 'アクセスを許可しました', denied: 'アクセスを許可しませんでした', href: '/principals', label: 'アクセス管理' },
  connect: { done: '接続しました', denied: '接続しませんでした', href: '/connections', label: '接続' },
  store: { done: '登録しました', denied: '登録しませんでした', href: '/credentials', label: '認証情報' },
  app: { done: 'OAuthアプリを登録しました', denied: '登録しませんでした', href: '/connections', label: '接続' },
};

export function requestResultView(row, error = '') {
  const kind = Object.hasOwn(kinds, row?.kind) ? kinds[row.kind] : undefined;
  const destination = kind ? { href: kind.href, label: kind.label } : { href: '/', label: 'ホーム' };
  if (!kind) return { ...destination, title: '依頼を確認できません', description: error || '依頼のリンクを開き直してください。', completed: false };
  if (row.status === 'done') return { ...destination, title: kind.done, description: 'この画面は閉じて構いません。', completed: true };
  if (row.status === 'denied') return { ...destination, title: kind.denied, description: '', completed: false };
  if (row.status === 'cancelled') return { ...destination, title: '依頼は取り消されました',
    description: row.reason === 'access_revoked' ? '依頼元へのアクセス許可が取り消されました。' : row.reason === 'requester_revoked' ? '依頼元の登録が削除されました。' : '', completed: false };
  return { ...destination, title: '依頼を確認できません', description: '依頼のリンクを開き直してください。', completed: false };
}

export const knownRequestKind = kind => Object.hasOwn(kinds, kind);
