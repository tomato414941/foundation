import { z } from 'zod';
import type { JsonApi } from '../shared/client.js';
import { CatalogMethod } from '../shared/contracts.js';
import { catalogDefinition } from '../shared/connection-methods.js';
import { RenewalOperation, SealedItem } from '../shared/protocol.js';
import type { ConnectionBroker } from './connections.js';
import { DomainError } from '../server/errors.js';

export class HttpBroker {
  readonly api: JsonApi;
  constructor(api: JsonApi) {
    this.api = { async json<T>(path: string, options = {}, schema?: z.ZodType<T>): Promise<T> {
      try { return await api.json(path, options, schema); }
      catch (error) {
        if (error instanceof Error && 'status' in error && typeof error.status === 'number' &&
          'code' in error && typeof error.code === 'string')
          throw new DomainError(error.status, error.code, error.message);
        throw error;
      }
    } };
  }
  connections(): ConnectionBroker {
    const api = this.api;
    return {
      method: async id => catalogDefinition(await api.json('/api/connections/' + id + '/method', {}, CatalogMethod)),
      prepare: (id, resourceId, expectedRevision) => api.json('/api/connection-operations', {
        method: 'POST', body: { id, resourceId, expectedRevision },
      }, RenewalOperation),
      dispatch: (id, fence) => api.json('/api/connection-operations/' + id + '/dispatch', {
        method: 'POST', body: { fence },
      }, RenewalOperation),
      commit: (id, fence, content) => api.json('/api/connection-operations/' + id + '/commit', {
        method: 'POST', body: { fence, content },
      }, SealedItem),
      uncertain: (id, fence) => api.json('/api/connection-operations/' + id + '/uncertain', { method: 'POST', body: { fence } }),
      abort: (id, fence) => api.json('/api/connection-operations/' + id + '/abort', { method: 'POST', body: { fence } }, RenewalOperation),
      state: id => api.json('/api/connections/' + id + '/operation', {}, RenewalOperation.nullable()),
    };
  }
}
