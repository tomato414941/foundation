import { readdirSync, readFileSync } from 'node:fs';
import { checkDefinition } from './service-definition.mjs';
import { oauthScheme, oauthClient, oauthSettings } from './schemes/oauth.mjs';
import { create as github } from './adapters/github/index.mjs';
import { create as google } from './adapters/google/index.mjs';
import { create as cloudflare } from './adapters/cloudflare/index.mjs';
import { create as ebay } from './adapters/ebay/index.mjs';
import { create as openrouter } from './adapters/openrouter/index.mjs';
import { create as aws } from './adapters/aws/index.mjs';

// The services Foundation knows by name: one definition each, in catalog/<id>.json, checked when the server starts.
// A service is added as a file; code is added only for a scheme data cannot describe, as an adapter named here.
const DIR = new URL('./catalog/', import.meta.url);
export const DEFINITIONS = readdirSync(DIR).filter(file => file.endsWith('.json')).sort()
  .map(file => checkDefinition(JSON.parse(readFileSync(new URL(file, DIR), 'utf8')), { catalog: true }));
export const ADAPTERS = { github, google, cloudflare, ebay, openrouter, aws };
for (const definition of DEFINITIONS) for (const scheme of Object.values(definition.auth_schemes)) {
  if (scheme.adapter && !ADAPTERS[scheme.adapter]) throw new Error('Unknown adapter ' + scheme.adapter + ' in ' + definition.id);
}
export function definitionOf(id) {
  const found = DEFINITIONS.find(definition => definition.id === id);
  if (!found) throw new Error('No service ' + id + ' in the catalog');
  return found;
}

// The schemes of a definition as they run: an adapter's, or the one data describes. fetcher replaces the network,
// for tests.
export function schemesOf(definition, env = {}, { fetcher } = {}) {
  const options = fetcher ? { fetcher } : {}, schemes = {};
  for (const [id, spec] of Object.entries(definition.auth_schemes)) {
    if (spec.adapter) schemes[id] = ADAPTERS[spec.adapter](env);
    else if (id === 'oauth') schemes[id] = oauthScheme(definition, oauthClient(definition, definition.id ? oauthSettings(definition, env) : {}, options));
  }
  return schemes;
}
// Every service in the catalog, as the server runs them.
export const builtins = (env = process.env) => DEFINITIONS.map(definition => ({ definition, schemes: schemesOf(definition, env) }));
// One service of the catalog, with the schemes given (a test's fakes) in place of those it would build.
export const entry = (id, schemes = {}, env = {}) => {
  const definition = definitionOf(id);
  return { definition, schemes: { ...schemesOf(definition, env), ...schemes } };
};
