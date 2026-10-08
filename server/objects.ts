import { randomUUID } from 'node:crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import type { Resources, ResourceRow } from './resources.js';
import type { Actor } from './authorization.js';
import type { Billing } from './billing.js';
import type { Configuration } from './config.js';
import { fail } from './errors.js';

export interface ObjectStore {
  readonly enabled: boolean;
  put(id: string, body: Uint8Array, contentType: string): Promise<void>;
  get(id: string): Promise<Uint8Array>;
  remove(id: string): Promise<void>;
  link(id: string, name: string, seconds: number): Promise<string>;
  // A file Foundation itself hands out, such as a template, as a link that works for a while.
  publish(name: string, body: Uint8Array, contentType: string, seconds: number): Promise<string>;
}
export class S3Objects implements ObjectStore {
  readonly client: S3Client;
  readonly enabled: boolean;
  constructor(readonly config: Configuration) {
    this.client = new S3Client({ region: config.AWS_REGION });
    this.enabled = Boolean(config.FOUNDATION_BUCKET);
  }
  private key(id: string) {
    if (!this.enabled) fail(503, 'storage_unavailable', 'Object storage is not configured.');
    return { Bucket: this.config.FOUNDATION_BUCKET, Key: 'objects/' + id };
  }
  async put(id: string, body: Uint8Array, contentType: string) {
    await this.client.send(
      new PutObjectCommand({
        ...this.key(id),
        Body: body,
        ContentType: contentType,
        ServerSideEncryption: 'AES256',
      }),
    );
  }
  async get(id: string) {
    const value = await this.client.send(new GetObjectCommand(this.key(id)));
    return new Uint8Array(await value.Body!.transformToByteArray());
  }
  async remove(id: string) {
    await this.client.send(new DeleteObjectCommand(this.key(id)));
  }
  async link(id: string, name: string, seconds: number) {
    return getSignedUrl(
      this.client,
      new GetObjectCommand({
        ...this.key(id),
        ResponseContentType: 'application/octet-stream',
        ResponseContentDisposition: "attachment; filename*=UTF-8''" + encodeURIComponent(name),
      }),
      { expiresIn: seconds },
    );
  }
  async publish(name: string, body: Uint8Array, contentType: string, seconds: number) {
    if (!this.enabled) fail(503, 'storage_unavailable', 'Object storage is not configured.');
    const target = { Bucket: this.config.FOUNDATION_BUCKET, Key: 'published/' + name };
    await this.client.send(
      new PutObjectCommand({ ...target, Body: body, ContentType: contentType, ServerSideEncryption: 'AES256' }),
    );
    return getSignedUrl(this.client, new GetObjectCommand(target), { expiresIn: seconds });
  }
}
export class Objects {
  constructor(
    readonly resources: Resources,
    readonly billing: Billing,
    readonly store: ObjectStore,
  ) {}
  async upload(
    actor: Actor,
    ownerId: string,
    name: string,
    body: Uint8Array,
    contentType: string,
    previous?: ResourceRow,
  ) {
    if (!this.store.enabled) fail(503, 'storage_unavailable', 'Object storage is not configured.');
    if (body.length > 25 * 1024 * 1024) fail(413, 'object_limit', 'Files can be up to 25 MiB.');
    if (!/^[\w!#$&^.+-]+\/[\w!#$&^.+-]+(?:;[\x20-\x7e]+)?$/u.test(contentType) || contentType.length > 200)
      fail(400, 'invalid_content_type', 'Choose a valid file content type.');
    if (previous) {
      if (previous.kind !== 'object' || previous.owner_id !== ownerId)
        fail(400, 'wrong_kind', 'Choose an object.');
      await this.resources.authorization.requireResource(actor, previous, 'update');
    } else if (!(await this.resources.authorization.canCreate(actor, ownerId, 'object')))
      fail(403, 'forbidden', 'You cannot upload files for this principal.');
    const id = previous?.id ?? randomUUID(),
      storageId = randomUUID();
    await this.resources.db.pool.query('INSERT INTO object_blobs(id) VALUES($1)', [storageId]);
    await this.store.put(storageId, body, contentType);
    let row: ResourceRow;
    try {
      row = await this.resources.db.transaction(async (connection) => {
        await this.billing.reserve(
          ownerId,
          'storage',
          body.length - Number(previous?.data.size ?? 0),
          connection,
        );
        const data = { size: body.length, contentType };
        // Each version has its own storage key, so a failed edit cannot overwrite the current file.
        const updated = previous
          ? await this.resources.update(previous, { name, data, privateData: storageId }, connection)
          : await this.resources.insert(
              ownerId,
              'object',
              name,
              data,
              { id, privateData: storageId },
              connection,
            );
        await connection.query('UPDATE object_blobs SET resource_id=NULL WHERE resource_id=$1', [id]);
        await connection.query('UPDATE object_blobs SET resource_id=$2 WHERE id=$1', [storageId, id]);
        await this.resources.audit.record(
          ownerId,
          actor.id,
          'object.upload',
          id,
          { bytes: body.length },
          connection,
        );
        return updated;
      });
    } catch (error) {
      await this.collectOne(storageId).catch(() => {});
      throw error;
    }
    if (previous?.private_data) await this.collectOne(previous.private_data).catch(() => {});
    return row;
  }
  async content(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'object') fail(400, 'wrong_kind', 'This item is not an object.');
    await this.resources.authorization.requireResource(actor, row, 'use');
    return this.store.get(row.private_data!);
  }
  async link(actor: Actor, row: ResourceRow, minutes = 15) {
    if (row.kind !== 'object') fail(400, 'wrong_kind', 'This item is not an object.');
    await this.resources.authorization.requireResource(actor, row, 'use');
    const url = await this.store.link(row.private_data!, row.name, minutes * 60);
    return { url, expiresAt: new Date(Date.now() + minutes * 60_000).toISOString() };
  }
  async remove(actor: Actor, row: ResourceRow) {
    await this.resources.authorization.requireResource(actor, row, 'delete');
    await this.resources.delete(actor, row);
    await this.collectOne(row.private_data!).catch(() => {});
  }
  private async collectOne(id: string) {
    await this.resources.db.transaction(async (connection) => {
      const row = await this.resources.db.one(
        'SELECT id FROM object_blobs WHERE id=$1 AND resource_id IS NULL FOR UPDATE',
        [id],
        connection,
      );
      if (!row) return;
      await this.store.remove(id);
      await connection.query('DELETE FROM object_blobs WHERE id=$1', [id]);
    });
  }
  async collect() {
    if (!this.store.enabled) return;
    const rows = await this.resources.db.all<{ id: string }>(
      "SELECT id FROM object_blobs WHERE resource_id IS NULL AND created_at<now()-interval '1 hour' LIMIT 50",
    );
    for (const row of rows) await this.collectOne(row.id);
  }
}
