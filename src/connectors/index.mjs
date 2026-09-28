import { create as github } from './github/index.mjs';
import { create as openrouter } from './openrouter/index.mjs';
import { create as google } from './google/index.mjs';
import { create as ebay } from './ebay/index.mjs';
import { create as cloudflare } from './cloudflare/index.mjs';
import { create as aws } from './aws/index.mjs';
import { create as oauth2 } from './oauth2/index.mjs';
import { create as services } from './services/index.mjs';

// Register a built-in here; its settings, metadata and behavior stay in its own directory.
export function builtins(env = process.env) { return [github, openrouter, google, ebay, cloudflare, aws, services, oauth2].flatMap(create => create(env)); }
