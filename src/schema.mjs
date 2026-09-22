import { fail } from './errors.mjs';

// A schema is what the owner hands over, as a list of fields.
//
// It is responsible for two things only: saying which values to receive, and
// accepting values of exactly that shape. It does not know the service, the
// screen it is shown on, how the service checks the values, or how they reach
// the runtime. Those belong to the method that holds the schema.
//
// A field:
//   id       the name the value is kept and submitted under
//   label    what the owner sees
//   kind     'line' one line | 'multiline' several lines | 'choice' one of options
//   secret   typed hidden and never shown back; other values may be shown to the owner
//   pattern  the shape a value must have, as a regular expression (optional)
//   max      the longest value accepted (optional; each kind has a ceiling)
//   options  for 'choice': [{ value, label }]
const KINDS = { line: 4096, multiline: 8192, choice: 64 };
const ID = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const plain = value => typeof value === 'string' && value.trim() !== '' && value.length <= 60 && !/[\x00-\x1f\x7f<>]/.test(value);

// Declares a schema. A malformed declaration is a mistake in whoever wrote it, so it throws.
export function defineSchema(fields) {
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > 8) throw new Error('A schema has one to eight fields.');
  const seen = new Set();
  return Object.freeze(fields.map(({ id, label, kind = 'line', secret = false, pattern, max, options }) => {
    if (!ID.test(id) || seen.has(id)) throw new Error('Field ids are unique identifiers: ' + id);
    if (!plain(label)) throw new Error('Field ' + id + ' needs a plain label of up to 60 characters.');
    if (!(kind in KINDS)) throw new Error('Field ' + id + ' has an unknown kind: ' + kind);
    if ((kind === 'choice') !== Array.isArray(options) || (options && !options.every(option => typeof option.value === 'string' && plain(option.label)))) throw new Error('Field ' + id + ' has options only if it is a choice.');
    if (pattern !== undefined) new RegExp(pattern);
    seen.add(id);
    return Object.freeze({ id, label, kind, secret: secret === true, max: Math.min(max || KINDS[kind], KINDS[kind]), ...(pattern ? { pattern } : {}), ...(options ? { options: Object.freeze(options.map(Object.freeze)) } : {}) });
  }));
}

// Accepts submitted values for exactly the schema's fields and nothing else.
// A value of the wrong shape is the owner's to correct, so it answers 400.
export function acceptValues(schema, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_values', '入力内容を確認してください。');
  return Object.fromEntries(schema.map(field => {
    const raw = typeof input[field.id] === 'string' ? input[field.id] : '';
    const value = field.kind === 'multiline' ? raw.replace(/\r\n?/g, '\n').trim() : raw.trim();
    const reject = message => fail(400, 'invalid_values', field.label + message);
    if (!value) reject('を入力してください。');
    if (value.length > field.max) reject('が長すぎます。');
    if (field.kind === 'line' && /\s/.test(value)) reject('に空白や改行は含められません。');
    if (field.kind === 'choice' && !field.options.some(option => option.value === value)) reject('を選んでください。');
    if (field.pattern && !new RegExp('^(?:' + field.pattern + ')$').test(value)) reject('の形式を確認してください。');
    return [field.id, value];
  }));
}
