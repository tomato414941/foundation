import { ja } from '../web/locales/server.js';
import { ja as serviceLabels } from '../web/locales/services.js';

export const IMPORT_MAP = '{"imports":{"i18next":"/vendor/i18next.js"}}';
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

// Domain modules and adapters remain locale-independent. Match their known messages
// only at the explicitly localized Web response boundary. Never translate a whole
// response recursively: names, stored secrets, provider values and API fields are data.
const exact = new Map();
const templates = [];
const quote = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
for (const [key, message] of Object.entries(ja)) {
  if (!key.startsWith('server.error.') || /_(one|other)$/.test(key)) continue;
  if (!message.includes('{{')) { exact.set(message, key); continue; }
  const names = [];
  let cursor = 0, pattern = '', specificity = 0;
  for (const part of message.matchAll(/\{\{(\w+)\}\}/g)) {
    const text = message.slice(cursor, part.index);
    pattern += quote(text) + '([\\s\\S]*?)';
    specificity += text.length;
    names.push(part[1]);
    cursor = part.index + part[0].length;
  }
  pattern += quote(message.slice(cursor));
  specificity += message.length - cursor;
  templates.push({ key, names, pattern: new RegExp('^' + pattern + '$'), specificity });
}
// More specific validation/provider sentences precede generic field-label templates.
templates.sort((left, right) => right.specificity - left.specificity);
const labels = new Map(Object.entries({ ...ja, ...serviceLabels })
  .filter(([key, value]) => (key.startsWith('server.label.') || key.endsWith('.label') || key.startsWith('service.oauth.')) && !value.includes('{{'))
  .map(([key, value]) => [value, key]));

export function localizeErrorMessage(message, t) {
  const key = exact.get(message);
  if (key) return t(key);
  for (const template of templates) {
    const match = template.pattern.exec(message);
    if (!match) continue;
    const values = Object.fromEntries(template.names.map((name, index) => {
      const value = match[index + 1];
      // Only a known built-in field label is language-bearing. Interpolated resource
      // names, hostnames, validation paths and user-defined labels stay untouched.
      return [name, name === 'count' && /^\d+$/.test(value) ? Number(value)
        : name === 'label' && labels.has(value) ? t(labels.get(value)) : value];
    }));
    return t(template.key, values);
  }
  // Unknown provider/custom messages are data, not translation keys.
  return message;
}
