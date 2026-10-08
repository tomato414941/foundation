import type { z } from 'zod';
import type { Database } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import { publicUrl } from './transport.js';
import type { Settings } from '../shared/contracts.js';

export class Integrations {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly origin: string,
  ) {}
  async get(actor: Actor, id: string) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    return (
      (await this.db.one<{ settings: z.infer<typeof Settings> }>(
        'SELECT settings FROM integration_settings WHERE principal_id=$1', [id],
      ))?.settings ?? {}
    );
  }
  async set(actor: Actor, id: string, settings: z.infer<typeof Settings>) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    for (const value of Object.values(settings)) if (value) publicUrl(value, this.origin);
    await this.db.pool.query(
      'INSERT INTO integration_settings(principal_id,settings) VALUES($1,$2) ON CONFLICT(principal_id) DO UPDATE SET settings=EXCLUDED.settings',
      [id, JSON.stringify(settings)],
    );
    return { settings };
  }
}
