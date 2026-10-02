import i18next from 'i18next';
import * as shared from './locales/shared.js';
import * as client from './locales/client.js';
import * as server from './locales/server.js';
import * as services from './locales/services.js';

export const SUPPORTED_LOCALES = Object.freeze(['ja', 'en']);
export const DEFAULT_LOCALE = 'ja';
export const LOCALE_COOKIE = 'foundation_locale';
export const isLocale = value => SUPPORTED_LOCALES.includes(value);
export const intlLocale = locale => locale === 'en' ? 'en-US' : 'ja-JP';

export const resources = Object.fromEntries(SUPPORTED_LOCALES.map(locale => [locale, {
  translation: { ...shared[locale], ...client[locale], ...server[locale], ...services[locale] },
}]));

// Every request gets its own instance. The browser owns one instance for its page;
// neither request detection nor changing a browser language mutates a server singleton.
export function createI18n(locale = DEFAULT_LOCALE) {
  const instance = i18next.createInstance();
  instance.init({
    lng: isLocale(locale) ? locale : DEFAULT_LOCALE,
    fallbackLng: DEFAULT_LOCALE,
    supportedLngs: SUPPORTED_LOCALES,
    load: 'languageOnly',
    resources,
    initAsync: false,
    keySeparator: false,
    // Translations produce text. HTML renderers escape the complete result at the
    // output boundary; textContent and native browser APIs must receive plain text.
    interpolation: { escapeValue: false },
    returnNull: false,
    returnEmptyString: false,
  });
  return instance;
}

// A deliberately small allowlist: cookie values never become resource paths or
// HTML. Invalid cookies are ignored, including malformed percent-encoding.
export function resolveLocale({ cookie = '', acceptLanguage = '' } = {}) {
  if (typeof cookie === 'string') {
    for (const part of cookie.split(';')) {
      const equal = part.indexOf('=');
      if (equal < 0 || part.slice(0, equal).trim() !== LOCALE_COOKIE) continue;
      try {
        const locale = decodeURIComponent(part.slice(equal + 1).trim());
        if (isLocale(locale)) return locale;
      } catch {}
    }
  }
  if (typeof acceptLanguage !== 'string') return DEFAULT_LOCALE;
  const preferred = acceptLanguage.split(',').map((range, index) => {
    const [tag, ...parameters] = range.trim().toLowerCase().split(';').map(value => value.trim());
    const quality = parameters.find(value => value.startsWith('q='));
    const validQuality = !quality || /^q=(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/.test(quality);
    const weight = validQuality ? (quality ? Number(quality.slice(2)) : 1) : 0;
    const language = /^[a-z]{2,8}(?:-[a-z0-9]{1,8})*$/.test(tag) ? tag.split('-')[0] : null;
    return { locale: tag === '*' ? DEFAULT_LOCALE : language, weight, index };
  }).filter(item => isLocale(item.locale) && item.weight > 0)
    .sort((a, b) => b.weight - a.weight || a.index - b.index);
  return preferred[0]?.locale || DEFAULT_LOCALE;
}

export function formatDate(value, locale = DEFAULT_LOCALE, options) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return new Intl.DateTimeFormat(intlLocale(locale), options ?? { dateStyle: 'short', timeStyle: 'medium' }).format(date);
}

export const formatNumber = (value, locale = DEFAULT_LOCALE, options) => new Intl.NumberFormat(intlLocale(locale), options).format(value);
export const compareText = (a, b, locale = DEFAULT_LOCALE) => new Intl.Collator(intlLocale(locale)).compare(String(a), String(b));
