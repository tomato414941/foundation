import { createI18n } from './i18n.js';
import { ja, en } from './locales/services.js';

const catalogIds = new Set([
  'airtable', 'asana', 'atlassian', 'aws', 'bitbucket', 'box', 'calendly', 'chatwork',
  'cloudflare', 'digitalocean', 'discord', 'dropbox', 'ebay', 'freee', 'github', 'gitlab',
  'google', 'heroku', 'hubspot', 'kintone', 'linear', 'microsoft', 'netlify', 'notion',
  'openrouter', 'salesforce', 'shopify', 'slack', 'spotify', 'x', 'zendesk', 'zoom',
]);
const appKeys = { client_id: 'service.oauth.clientId', client_secret: 'service.oauth.clientSecret' };

// appFieldsOf inserts this pair for every OAuth app, including custom services.
// A owner's field definition cannot contain `sealed`, so the sealed secret and
// its immediately preceding client ID identify Foundation's own fields without
// matching text or translating any owner-defined label with the same name.
function generatedAppFieldIndexes(service) {
  if (typeof service?.catalog !== 'boolean') return [];
  const fields = service.auth_schemes?.oauth?.app_fields;
  if (!Array.isArray(fields)) return [];
  const canonical = (field, name) => field?.name === name && field.required === true
    && [ja[appKeys[name]], en[appKeys[name]]].includes(field.label)
    && Object.keys(field).every(key => ['name', 'label', 'required', ...(name === 'client_secret' ? ['sealed'] : [])].includes(key));
  const secret = fields.findIndex(field => canonical(field, 'client_secret') && field.sealed === true);
  return secret > 0 && canonical(fields[secret - 1], 'client_id') ? [secret - 1, secret] : [];
}

// Only catalog:true is evidence that service-specific field text is ours. A
// owner's service can use exactly the same names or labels as a catalog entry;
// those remain their content. The generated OAuth pair is Foundation's in both.
// Return a presentation copy so changing language never mutates cached API data.
export function localizeService(service, locale = 'ja') {
  if (!service?.auth_schemes) return service;
  const builtin = service.catalog === true && catalogIds.has(service.id);
  const appIndexes = generatedAppFieldIndexes(service);
  if (!builtin && !appIndexes.length) return service;
  const { t } = createI18n(locale);
  if (!builtin && appIndexes.every(index => {
    const field = service.auth_schemes.oauth.app_fields[index];
    return field.label === t(appKeys[field.name]);
  })) return service;
  const translate = (key, original) => Object.hasOwn(ja, key) ? t(key) : original;
  const auth_schemes = Object.fromEntries(Object.entries(service.auth_schemes).map(([name, scheme]) => {
    if (!builtin && name !== 'oauth') return [name, scheme];
    const prefix = `service.${service.id}.${name}`, localized = { ...scheme };
    if (builtin && scheme.instructions) localized.instructions = translate(`${prefix}.instructions`, scheme.instructions);
    for (const group of ['fields', 'app_fields']) {
      if (!Array.isArray(scheme[group])) continue;
      localized[group] = scheme[group].map((field, index) => {
        const result = { ...field };
        for (const property of ['label', 'placeholder', 'note']) {
          if (!Object.hasOwn(field, property)) continue;
          const generated = name === 'oauth' && group === 'app_fields' && appIndexes.includes(index) && property === 'label';
          if (generated) result[property] = t(appKeys[field.name]);
          else if (builtin) result[property] = translate(`${prefix}.${group}.${field.name}.${property}`, field[property]);
        }
        return result;
      });
    }
    return [name, localized];
  }));
  return { ...service, auth_schemes };
}
