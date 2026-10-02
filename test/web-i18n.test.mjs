import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createI18n, resolveLocale, formatDate, formatNumber, compareText, resources } from '../web/i18n.js';

test('the explicit supported cookie takes precedence over weighted browser preferences', () => {
  assert.equal(resolveLocale({ cookie: 'fdn_session=private; foundation_locale=en', acceptLanguage: 'ja' }), 'en');
  assert.equal(resolveLocale({ cookie: 'foundation_locale=ja', acceptLanguage: 'en-US,en;q=0.9' }), 'ja');
  assert.equal(resolveLocale({ cookie: 'foundation_locale=%65%6e' }), 'en');
  assert.equal(resolveLocale({ cookie: 'foundation_locale=fr', acceptLanguage: 'en-GB' }), 'en');
  assert.equal(resolveLocale({ cookie: 'foundation_locale=%E0%A4%A', acceptLanguage: 'en' }), 'en');
  assert.equal(resolveLocale({ cookie: 'foundation_locale=<script>', acceptLanguage: 'ja' }), 'ja');
});

test('regional browser tags and weights resolve to JA or EN with a Japanese compatibility fallback', () => {
  for (const [acceptLanguage, expected] of [
    ['en-US,en;q=0.9,ja;q=0.8', 'en'], ['en;q=0.5,ja-JP;q=0.9', 'ja'],
    ['fr-CA,fr;q=0.9,en-GB;q=0.8', 'en'], ['EN-us', 'en'],
    ['ja;q=0,en;q=0.5', 'en'], ['ja;q=oops,en;q=0.4', 'en'],
    ['en;q=2,ja;q=0.8', 'ja'], ['en;q=-1', 'ja'], ['fr,de;q=0.8', 'ja'],
    ['en;q=0.7,ja;q=0.7', 'en'], ['', 'ja'], ['*', 'ja'],
  ]) assert.equal(resolveLocale({ acceptLanguage }), expected, acceptLanguage);
});

test('locale instances are independent and unknown locales fall back to Japanese', async () => {
  const ja = createI18n('ja'), en = createI18n('en'), fallback = createI18n('zz');
  assert.equal(ja.language, 'ja');
  assert.equal(en.language, 'en');
  assert.equal(fallback.language, 'ja');
  await en.changeLanguage('ja');
  assert.equal(ja.language, 'ja');
  const nextEnglish = createI18n('en');
  assert.equal(nextEnglish.language, 'en');
});

test('Japanese and English dictionaries have exactly matching keys and interpolation variables', async () => {
  const modules = (await readdir(new URL('../web/locales/', import.meta.url))).filter(name => name.endsWith('.js'));
  const seen = new Set();
  const placeholders = value => [...new Set([...value.matchAll(/{{\s*-?\s*([^},\s]+)(?:,[^}]*)?\s*}}/g)].map(match => match[1]))].sort();
  for (const module of modules) {
    const { ja, en } = await import(`../web/locales/${module}`);
    assert.deepEqual(Object.keys(ja).sort(), Object.keys(en).sort(), `${module}: key parity`);
    for (const key of Object.keys(ja)) {
      assert.match(key, /^[a-zA-Z][\w.-]*$/, `${module}: semantic key ${key}`);
      assert.ok(!seen.has(key), `duplicate key ${key}`);
      seen.add(key);
      assert.equal(typeof ja[key], 'string', key);
      assert.equal(typeof en[key], 'string', key);
      assert.deepEqual(placeholders(ja[key]), placeholders(en[key]), `${module}: ${key}`);
    }
  }
  assert.ok(seen.size > 100, 'the complete Web surface has translated resources');
});

test('literal translation lookups resolve in both locales, including plural families', async () => {
  for (const filename of ['app.js', 'workspace-view.js', 'request-view.js', 'service-i18n.js']) {
    const source = await readFile(new URL('../web/' + filename, import.meta.url), 'utf8');
    for (const [, key] of source.matchAll(/\bt\(\s*['"]([^'"]+)['"]/g)) {
      for (const locale of ['ja', 'en']) {
        const dictionary = resources[locale].translation;
        assert.ok(Object.hasOwn(dictionary, key) || Object.hasOwn(dictionary, key + '_other'), `${filename}: ${locale}:${key}`);
      }
    }
  }
});

test('Intl supplies locale-aware numbers, date/time and collation', () => {
  assert.equal(formatNumber(1234567.5, 'en'), '1,234,567.5');
  const date = Date.UTC(2026, 9, 2, 13, 4);
  assert.equal(formatDate(date, 'en', { month: 'long', day: 'numeric', timeZone: 'UTC' }), 'October 2');
  assert.equal(formatDate(date, 'ja', { month: 'long', day: 'numeric', timeZone: 'UTC' }), '10月2日');
  assert.equal(formatDate('not a date', 'en'), '—');
  assert.equal(Math.sign(compareText('apple', 'banana', 'en')), -1);
});
