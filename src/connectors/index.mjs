import { create as github } from './github/index.mjs';
import { create as openrouter } from './openrouter/index.mjs';
import { create as gcp } from './gcp/index.mjs';
import { create as gmail } from './gmail/index.mjs';
import { create as ebay } from './ebay/index.mjs';
import { create as cloudflare } from './cloudflare/index.mjs';

// Register a built-in here; its settings, metadata and behavior stay in its own directory.
export function builtins(env = process.env) { return [github, openrouter, gcp, gmail, ebay, cloudflare].flatMap(create => create(env)); }
