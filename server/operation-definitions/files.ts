import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { fail } from '../errors.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, bodyObject, withId } from './support.js';

export function defineFiles(definitions: DefinitionRegistry, services: Pick<OperationServices, 'resources' | 'files'>) {
  const { resources, files } = services;
  const bind = definitions.bind.bind(definitions);
  const fileLimit = 25 * 1024 * 1024;
  const fileContent = z.object({ bytes: z.string().max(Math.ceil(fileLimit * 4 / 3)).regex(/^[A-Za-z0-9_-]*$/),
    contentType: z.string().max(200).default('application/octet-stream') }).strict();
  const binary = (body: unknown) => {
    if (!Buffer.isBuffer(body)) fail(400, 'binary_required', 'Upload the file as application/octet-stream.');
    return body.toString('base64url');
  };
  definitions.define('file.create', fileContent.extend({ ownerId: C.Id, name: C.Name }), ['ファイルを保存する', 'Save a file'],
    async (who, input) => resources.view(who, await files.upload(who, input.ownerId, input.name,
      Buffer.from(input.bytes, 'base64url'), input.contentType)));
  bind({ name: 'file.create', method: 'POST', path: '/api/principals/:id/files', bodyLimit: fileLimit,
    schema: { params: C.IdParams, querystring: fileContent.omit({ bytes: true }).extend({ name: C.Name }), response: { 201: C.Resource } },
    input: (params, body, query) => ({ ...bodyObject(query), ownerId: params.id, bytes: binary(body) }), status: 201 });
  definitions.define('file.update', fileContent.extend({ id: C.Id, version: z.number().int().positive() }),
    ['ファイルを更新する', 'Update a file'], async (who, input) => {
      const row = await resources.get(input.id);
      if (row.version !== input.version) fail(409, 'changed', 'This file changed. Reload it before saving.');
      return resources.view(who, await files.upload(who, row.owner_id, row.name, Buffer.from(input.bytes, 'base64url'), input.contentType, row));
    });
  bind({ name: 'file.update', method: 'PUT', path: '/api/resources/:id/content', bodyLimit: fileLimit,
    schema: { params: C.IdParams, querystring: fileContent.omit({ bytes: true }).extend({ version: z.coerce.number().int().positive() }),
      response: { 200: C.Resource } }, input: (params, body, query) => ({ ...bodyObject(query), id: params.id, bytes: binary(body) }) });
  const link = idInput.extend({ minutes: z.number().int().min(1).max(1440).default(15) });
  definitions.define('file.link', link, ['ファイルのリンクを作る', 'Create a file link'], async (who, input) => files.link(who, await resources.get(input.id), input.minutes));
  bind({ name: 'file.link', method: 'POST', path: '/api/resources/:id/link', schema: { params: C.IdParams,
    body: link.omit({ id: true }), response: { 200: z.object({ url: z.url(), expiresAt: C.Time }) } }, input: withId });
}
