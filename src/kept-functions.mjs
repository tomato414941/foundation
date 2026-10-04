import { randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';
import { prepare as prepareFetch } from './fetch.mjs';

const FUNCTIONS_MAX = 100, PARAMETERS_MAX = 16, QUERY_MAX = 16;
const PARAMETER_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const invalid = message => fail(400, 'invalid_function', message);

// A function a principal keeps: one decided operation, called by name with arguments. What it sends, where, and
// with which of its owner's connections and secrets is the owner's to say, once, here; whoever calls it gives only
// the arguments it declares. So being let to call one is narrower than being let to use what it uses.
//
// Its request is the HTTPS request of fetch.mjs, with one more kind of part: { parameter: name }, where an
// argument goes. Arguments may also be put in the query, beside what is written there; the host and the path are
// never an argument's.
const isParameter = part => part && typeof part === 'object' && !Array.isArray(part) && Object.keys(part).length === 1 && typeof part.parameter === 'string';

function definitionInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['description', 'parameters', 'request', 'query'].includes(key))) invalid('ファンクションの定義を確認してください。');
  const description = input.description ?? '';
  if (typeof description !== 'string' || description.length > 500) invalid('説明は500文字までで指定してください。');
  const parameters = input.parameters ?? {};
  if (typeof parameters !== 'object' || Array.isArray(parameters) || Object.keys(parameters).length > PARAMETERS_MAX) invalid(`引数は${PARAMETERS_MAX}件までで指定してください。`);
  for (const [name, spec] of Object.entries(parameters)) {
    if (!PARAMETER_NAME.test(name)) invalid('引数の名前は英小文字で始まる英数字とアンダースコアで指定してください。');
    if (!spec || typeof spec !== 'object' || Array.isArray(spec) || Object.keys(spec).some(key => !['description', 'required'].includes(key))
      || (spec.description !== undefined && (typeof spec.description !== 'string' || spec.description.length > 300))
      || (spec.required !== undefined && typeof spec.required !== 'boolean')) invalid('引数の定義を確認してください。');
  }
  const declared = part => { if (!Object.hasOwn(parameters, part.parameter)) invalid(`引数 ${part.parameter} が定義されていません。`); };
  if (!input.request || typeof input.request !== 'object' || Array.isArray(input.request) || Object.hasOwn(input.request, 'save')) invalid('送るリクエストを指定してください。');
  // The request is checked as one that would be sent: each argument stands in as text while it is.
  const bindings = Array.isArray(input.request.bindings) ? input.request.bindings : input.request.bindings === undefined ? [] : invalid('bindings を確認してください。');
  const stood = bindings.map(binding => !binding || !Array.isArray(binding.parts) ? binding
    : { ...binding, parts: binding.parts.map(part => { if (isParameter(part)) { declared(part); return ''; } return part; }) });
  const prepared = prepareFetch({ ...input.request, bindings: stood }, []);
  const query = input.query ?? {};
  if (typeof query !== 'object' || Array.isArray(query) || Object.keys(query).length > QUERY_MAX) invalid(`query は${QUERY_MAX}件までで指定してください。`);
  for (const [name, parts] of Object.entries(query)) {
    if (!name || name.length > 200 || !Array.isArray(parts) || !parts.length || parts.length > 32
      || parts.some(part => !(typeof part === 'string' ? part.length <= 2000 : isParameter(part)))) invalid('query は文字列と引数の並びで指定してください。');
    parts.filter(isParameter).forEach(declared);
  }
  return { definition: { description, parameters, request: input.request, query }, references: [...prepared.references.values()] };
}

export class KeptFunctions {
  // inputs: what a reference to a connection or a secret resolves to, asked as the owner.
  constructor(store, resources, inputs) { Object.assign(this, { store, db: store.db, resources, inputs }); }
  row(id) { return this.db.prepare(`SELECT r.id,r.owner_id,r.kind,r.name,r.created_at,r.updated_at,f.definition FROM functions f JOIN resources r ON r.id=f.resource_id WHERE r.id=?`).get(id); }
  find(ownerId, name) {
    const found = this.db.prepare("SELECT id FROM resources WHERE owner_id=? AND kind='function' AND name=?").get(ownerId, name);
    return found ? this.row(found.id) : undefined;
  }
  list(ownerId) { return this.db.prepare("SELECT id FROM resources WHERE owner_id=? AND kind='function' ORDER BY name").all(ownerId).map(found => this.row(found.id)); }
  // Kept under the owner's name for it; the same name again replaces what it does. What it refers to must be the
  // owner's own, now: a connection or a secret it holds.
  put(ownerId, name, input) {
    resourceName(name);
    const { definition, references } = definitionInput(input);
    for (const reference of references) this.inputs.resolve(ownerId, reference);
    return this.store.transaction(() => {
      const existing = this.find(ownerId, name);
      if (!existing && this.list(ownerId).length >= FUNCTIONS_MAX) fail(409, 'function_limit', `ファンクションは${FUNCTIONS_MAX}件までです。`);
      const id = existing?.id ?? randomUUID();
      if (existing) { this.db.prepare('UPDATE functions SET definition=? WHERE resource_id=?').run(JSON.stringify(definition), id); this.resources.touch(id); }
      else { this.resources.insert(id, ownerId, 'function', name); this.db.prepare('INSERT INTO functions (resource_id,definition) VALUES (?,?)').run(id, JSON.stringify(definition)); }
      return this.row(id);
    });
  }
  write(row, input) { return this.put(row.owner_id, row.name, input); }
  rename(row, name) {
    resourceName(name);
    if (name !== row.name && this.find(row.owner_id, name)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.row(this.resources.rename(row, name).id);
  }
  // It goes to another owner only when it uses nothing of this one's: what it refers to would not go with it.
  transfer(row, ownerId) {
    const { references } = definitionInput(JSON.parse(row.definition));
    if (references.length) fail(409, 'function_refers', 'このファンクションは持ち主の接続やシークレットを使うため、渡せません。');
    return this.row(this.resources.transfer(row, ownerId).id);
  }
  remove(row) { this.resources.remove(row); }
  // The request one call sends: what was decided, with the caller's arguments where it says they go. An argument is
  // text, put in as it is; what was not given and was not required is empty.
  call(row, given = {}) {
    const { parameters, request, query } = JSON.parse(row.definition);
    if (!given || typeof given !== 'object' || Array.isArray(given)) fail(400, 'invalid_arguments', '引数は名前と文字列の組で指定してください。');
    for (const [name, value] of Object.entries(given)) {
      if (!Object.hasOwn(parameters, name)) fail(400, 'invalid_arguments', `引数 ${name} はこのファンクションにありません。`);
      if (typeof value !== 'string' || value.length > 100_000) fail(400, 'invalid_arguments', `引数 ${name} は文字列で指定してください。`);
    }
    for (const [name, spec] of Object.entries(parameters)) if (spec.required && !Object.hasOwn(given, name)) fail(400, 'invalid_arguments', `引数 ${name} を指定してください。`);
    const text = part => typeof part === 'string' ? part : isParameter(part) ? given[part.parameter] ?? '' : part;
    // Arguments beside one another become one text, so that none of them is taken for a reference.
    const joined = parts => parts.reduce((out, part) => { const value = text(part); if (typeof value === 'string' && typeof out.at(-1) === 'string') out[out.length - 1] += value; else out.push(value); return out; }, []);
    const url = new URL(request.url);
    for (const [name, parts] of Object.entries(query)) url.searchParams.append(name, parts.map(text).join(''));
    return { ...request, url: url.href, bindings: (request.bindings ?? []).map(binding => ({ ...binding, parts: joined(binding.parts) })) };
  }
  view(row) { return { ...this.resources.view(row), ...JSON.parse(row.definition) }; }
}
