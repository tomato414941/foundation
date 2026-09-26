const kinds = {
  actor: { done: '承認しました', denied: '承認しませんでした', href: '/principals', label: 'アクセスキー' },
  connect: { done: '接続しました', denied: '接続しませんでした', href: '/grants', label: '委任' },
  store: { done: '預けました', denied: '預けませんでした', href: '/grants', label: '委任' },
};

export function requestResultView(row, error = '') {
  const kind = Object.hasOwn(kinds, row?.kind) ? kinds[row.kind] : undefined;
  const destination = kind ? { href: kind.href, label: kind.label } : { href: '/', label: 'ホーム' };
  if (!kind) return { ...destination, title: '依頼を確認できません', description: error || '依頼のリンクを開き直してください。', completed: false };
  if (row.status === 'done') return { ...destination, title: kind.done, description: 'この画面は閉じて構いません。', completed: true };
  if (row.status === 'denied') return { ...destination, title: kind.denied, description: '', completed: false };
  if (row.status === 'cancelled') return { ...destination, title: '依頼は取り消されました',
    description: row.reason === 'requester_revoked' ? '依頼元のアクセスキーが失効しました。' : '', completed: false };
  return { ...destination, title: '依頼を確認できません', description: '依頼のリンクを開き直してください。', completed: false };
}

export const knownRequestKind = kind => Object.hasOwn(kinds, kind);
