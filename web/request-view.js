import { createI18n } from './i18n.js';

const japanese = createI18n('ja').t;
// Whether a request took on its asker: the one call one nobody knew may ask for, to act for whoever answers.
export const takesOn = row => row?.operations?.length === 1 && row.operations[0].operation_id === 'addRelation'
  && row.operations[0].body?.relation === 'agent' && row.operations[0].body?.object_id === 'me';

// What became of a request, said to the one who answered it.
export function requestResultView(row, error = '', t = japanese) {
  const taking = takesOn(row);
  const destination = taking ? { href: '/principals', label: t('nav.principals') } : { href: '/', label: t('nav.home') };
  if (!row) return { ...destination, title: t('request.result.unavailable'), description: error || t('request.result.reopen'), completed: false };
  if (row.status === 'granted') return { ...destination, title: t(taking ? 'request.result.agentGranted' : 'request.result.granted'), description: t('request.result.close'), completed: true };
  if (row.status === 'denied') return { ...destination, title: t(taking ? 'request.result.agentDenied' : 'request.result.denied'), description: '', completed: false };
  if (row.status === 'cancelled') return { ...destination, title: t('request.result.cancelled'),
    description: row.reason === 'access_revoked' ? t('request.result.accessRevoked') : row.reason === 'requester_revoked' ? t('request.result.requesterRevoked') : '', completed: false };
  return { ...destination, title: t('request.result.unavailable'), description: t('request.result.reopen'), completed: false };
}
