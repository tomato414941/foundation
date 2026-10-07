import { randomBytes, randomUUID } from 'node:crypto';
import { Webhook } from 'standardwebhooks';
import type { z } from 'zod';
import type { Database } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import { Vault } from './vault.js';
import type { Transport } from './transport.js';
import { publicUrl } from './transport.js';
import type { Settings, JsonValue } from '../shared/contracts.js';

export class Integrations {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly vault: Vault,
    readonly transport: Transport,
    readonly origin: string,
  ) {}
  async get(actor: Actor, id: string) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    return (
      (
        await this.db.one<{ settings: z.infer<typeof Settings> }>(
          'SELECT settings FROM integration_settings WHERE principal_id=$1',
          [id],
        )
      )?.settings ?? {}
    );
  }
  async set(actor: Actor, id: string, settings: z.infer<typeof Settings>) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    for (const value of Object.values(settings)) if (value) publicUrl(value, this.origin);
    const secret = 'whsec_' + randomBytes(32).toString('base64');
    const existing = await this.db.one('SELECT 1 FROM integration_settings WHERE principal_id=$1', [id]);
    await this.db.pool.query(
      'INSERT INTO integration_settings(principal_id,settings,webhook_secret) VALUES($1,$2,$3) ON CONFLICT(principal_id) DO UPDATE SET settings=EXCLUDED.settings',
      [id, JSON.stringify(settings), await this.vault.encrypt(secret, 'integration:' + id)],
    );
    return { settings, ...(!existing ? { webhookSecret: secret } : {}) };
  }
  async rotate(actor: Actor, id: string) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    const secret = 'whsec_' + randomBytes(32).toString('base64');
    await this.db.pool.query(
      "INSERT INTO integration_settings(principal_id,settings,webhook_secret) VALUES($1,'{}',$2) ON CONFLICT(principal_id) DO UPDATE SET webhook_secret=$2",
      [id, await this.vault.encrypt(secret, 'integration:' + id)],
    );
    return { webhookSecret: secret };
  }
  async enqueue(id: string, payload: Record<string, JsonValue>) {
    const configured = await this.db.one<{ settings: z.infer<typeof Settings> }>(
      'SELECT settings FROM integration_settings WHERE principal_id=$1',
      [id],
    );
    if (configured?.settings.webhookUrl)
      await this.db.pool.query('INSERT INTO webhooks(id,principal_id,payload) VALUES($1,$2,$3)', [
        randomUUID(),
        id,
        JSON.stringify(payload),
      ]);
  }
  async deliver() {
    await this.db.transaction(async (connection) => {
      const event = await this.db.one<{
        id: string;
        principal_id: string;
        payload: Record<string, JsonValue>;
        attempts: number;
        settings: z.infer<typeof Settings>;
        webhook_secret: string;
      }>(
        `SELECT w.*,s.settings,s.webhook_secret FROM webhooks w JOIN integration_settings s ON s.principal_id=w.principal_id WHERE delivered_at IS NULL AND attempts<10 AND next_attempt<=now() ORDER BY next_attempt FOR UPDATE OF w SKIP LOCKED LIMIT 1`,
        [],
        connection,
      );
      if (!event) return;
      const url = event.settings.webhookUrl;
      if (!url) {
        await connection.query('UPDATE webhooks SET delivered_at=now() WHERE id=$1', [event.id]);
        return;
      }
      const body = JSON.stringify({ ...event.payload, id: event.id }),
        secret = await this.vault.decrypt<string>(event.webhook_secret, 'integration:' + event.principal_id),
        timestamp = new Date();
      const signature = new Webhook(secret).sign(event.id, timestamp, body);
      let delivered = false;
      try {
        const result = await this.transport.send({
          url,
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'webhook-id': event.id,
            'webhook-timestamp': String(Math.floor(timestamp.getTime() / 1000)),
            'webhook-signature': signature,
          },
          body,
        });
        delivered = result.status >= 200 && result.status < 300;
      } catch {}
      await connection.query(
        "UPDATE webhooks SET attempts=attempts+1,delivered_at=CASE WHEN $2 THEN now() ELSE NULL END,next_attempt=now()+$3::int*interval '1 second' WHERE id=$1",
        [event.id, delivered, Math.min(86400, 30 * 2 ** event.attempts)],
      );
    });
  }
}
