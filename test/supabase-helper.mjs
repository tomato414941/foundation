import { SupabaseProvider, SUPABASE_API } from '../src/providers/supabase.mjs';
import { supabaseConnection, gmailConnection } from '../src/providers/catalog.mjs';
import { FakeGmail, fixture, json } from './helpers.mjs';

export const SUPABASE_TOKEN = 'sbp_' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0';
export class FakeSupabase extends SupabaseProvider {
  constructor() {
    super({ fetcher: (url, options) => this.fetch(url, options) });
    this.calls = [];
    this.profile = { gotrue_id: 'user-1', primary_email: 'Owner@Example.test', username: 'owner@example.test' };
    this.organizations = [{ id: 'org-1', slug: 'ttgx', name: 'Owner Org' }];
    this.valid = new Set([SUPABASE_TOKEN]);
  }
  async fetch(url, options) {
    this.calls.push({ url, options });
    if (!url.startsWith(SUPABASE_API + '/v1/') || (options.method && options.method !== 'GET')) throw new Error('Only Management API reads are allowed in tests: ' + url);
    if (this.handler) return this.handler(url, options);
    if (!this.valid.has(options.headers.authorization?.slice(7))) return json({ message: 'Unauthorized' }, 401);
    if (url.endsWith('/v1/profile')) return json(this.profile);
    if (url.endsWith('/v1/organizations')) return json(this.organizations);
    return json({ message: 'not found' }, 404);
  }
}

export async function supabaseFixture(t, options = {}) {
  const supabase = options.supabase || new FakeSupabase(), gmail = new FakeGmail();
  const f = await fixture(t, { gmail, integrations: [supabaseConnection(supabase), gmailConnection(gmail)], ...options });
  const importSupabase = (extra = {}) => f.request('/api/connections/supabase/connect', { method: 'POST', data: { name: 'Supabase', mode: 'access-token', token: SUPABASE_TOKEN, ...extra } });
  async function supabaseAccount(extra = {}) {
    const result = await importSupabase(extra);
    if (result.status !== 200) throw new Error(result.text);
    return (await f.request('/api/state')).json.accounts.find(account => account.id === result.json.account_id);
  }
  return { ...f, supabase, importSupabase, supabaseAccount };
}
