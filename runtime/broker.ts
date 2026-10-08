import type { ConnectionLabelValues } from '../shared/connections.js';
import { z } from 'zod';
import type { JsonApi } from '../shared/client.js';
import { Id } from '../shared/contracts.js';
import type { CustodyContent } from '../shared/custody.js';
import type { SignedReceipt } from '../shared/execution.js';
import { ClaimedExecution, OAuthRelay, ProtectedContent, RenewalOperation, Task } from '../shared/protocol.js';
import type { ExecutionBroker } from './executor.js';
import type { ConnectionBroker } from './connections.js';
import { DomainError } from '../server/errors.js';

export class HttpBroker implements ExecutionBroker {
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
  claim(id: string) { return this.api.json('/api/environments/' + id + '/claim', { method: 'POST', body: {} }, ClaimedExecution); }
  renew(id: string, lease: string) {
    return this.api.json('/api/executions/' + id + '/renew', { method: 'POST', body: { lease } }, z.object({ active: z.boolean() }));
  }
  dispatch(id: string, lease: string) { return this.api.json('/api/executions/' + id + '/dispatch', { method: 'POST', body: { lease } }); }
  finish(lease: string, receipt: SignedReceipt) {
    return this.api.json('/api/executions/' + receipt.id + '/finish', { method: 'POST', body: { lease, receipt } }, Task);
  }
  capture(name: string, content: CustodyContent, labels?: ConnectionLabelValues) {
    return this.api.json('/api/executor/outputs', { method: 'POST', body: { name, content, ...(labels ? { labels } : {}) } },
      z.object({ id: Id }));
  }
  connections(): ConnectionBroker {
    const api = this.api;
    return {
      relay: input => api.json('/api/oauth/relays', { method: 'POST', body: input }, OAuthRelay),
      capture: (name, content, labels) => this.capture(name, content, labels),
      prepare: (id, resourceId, expectedRevision) => api.json('/api/connection-operations', {
        method: 'POST', body: { id, resourceId, expectedRevision },
      }, RenewalOperation),
      dispatch: (id, fence) => api.json('/api/connection-operations/' + id + '/dispatch', {
        method: 'POST', body: { fence },
      }, RenewalOperation),
      commit: (id, fence, content) => api.json('/api/connection-operations/' + id + '/commit', {
        method: 'POST', body: { fence, content },
      }, ProtectedContent),
      uncertain: (id, fence) => api.json('/api/connection-operations/' + id + '/uncertain', { method: 'POST', body: { fence } }),
      abort: (id, fence) => api.json('/api/connection-operations/' + id + '/abort', { method: 'POST', body: { fence } }, RenewalOperation),
      state: id => api.json('/api/connections/' + id + '/operation', {}, RenewalOperation.nullable()),
    };
  }
}
