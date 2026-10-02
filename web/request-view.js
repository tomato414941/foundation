import { createI18n } from './i18n.js';

const japanese = createI18n('ja').t;
const kinds = {
  relation: { done: 'request.result.relationGranted', denied: 'request.result.relationDenied', href: '/principals', label: 'nav.principals' },
  connection: { done: 'request.result.connectionGranted', denied: 'request.result.connectionDenied', href: '/services', label: 'nav.services' },
  secret: { done: 'request.result.secretGranted', denied: 'request.result.secretDenied', href: '/secrets', label: 'nav.secrets' },
  app: { done: 'request.result.appGranted', denied: 'request.result.appDenied', href: '/services', label: 'nav.services' },
};
// What a request asks, as its one authorization detail.
export const detailOf = row => row?.authorization_details?.[0] ?? {};

export function requestResultView(row, error = '', t = japanese) {
  const type = detailOf(row).type, acting = type === 'relation' && detailOf(row).relation === 'agent';
  const kind = acting ? { ...kinds.relation, done: 'request.result.agentGranted', denied: 'request.result.agentDenied' } : Object.hasOwn(kinds, type) ? kinds[type] : undefined;
  const destination = kind ? { href: kind.href, label: t(kind.label) } : { href: '/', label: t('nav.home') };
  if (!kind) return { ...destination, title: t('request.result.unavailable'), description: error || t('request.result.reopen'), completed: false };
  if (row.status === 'granted') return { ...destination, title: t(kind.done), description: t('request.result.close'), completed: true };
  if (row.status === 'denied') return { ...destination, title: t(kind.denied), description: '', completed: false };
  if (row.status === 'cancelled') return { ...destination, title: t('request.result.cancelled'),
    description: row.reason === 'access_revoked' ? t('request.result.accessRevoked') : row.reason === 'requester_revoked' ? t('request.result.requesterRevoked') : '', completed: false };
  return { ...destination, title: t('request.result.unavailable'), description: t('request.result.reopen'), completed: false };
}

export const knownRequestKind = kind => Object.hasOwn(kinds, kind);
