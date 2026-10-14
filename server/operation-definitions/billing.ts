import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { DefinitionRegistry } from '../definitions.js';
import type { OperationServices } from '../builtin-definitions.js';
import { idInput, withId, ok } from './support.js';

export function defineBilling(definitions: DefinitionRegistry, services: Pick<OperationServices, 'billing' | 'integrations'>) {
  const { billing, integrations } = services;
  const bind = definitions.bind.bind(definitions);
  const limits = idInput.extend({ storageBytes: z.number().int().min(1).max(1_000_000_000_000),
    computeSeconds: z.number().int().min(1).max(10_000_000) });
  definitions.define('billing.limits', limits, ['利用上限を設定する', 'Set usage limits'], async (who, input) => {
    await billing.limits(who, input.id, input.storageBytes, input.computeSeconds); return ok();
  });
  bind({ name: 'billing.limits', method: 'PUT', path: '/api/principals/:id/limits', schema: { params: C.IdParams,
    body: limits.omit({ id: true }), response: { 200: C.Ok } }, input: withId });
  for (const name of ['checkout', 'portal'] as const) {
    definitions.define('billing.' + name, idInput, name === 'checkout' ? ['支払い方法を登録する', 'Add a payment method'] : ['支払いを管理する', 'Manage payment'],
      (who, input) => billing[name](who, input.id));
    bind({ name: 'billing.' + name, method: 'POST', path: '/api/principals/:id/payment/' + name, schema: { params: C.IdParams,
      body: z.object({}).strict(), response: { 200: z.object({ url: z.url() }) } }, input: params => params });
  }
  definitions.define('settings.update', z.object({ id: C.Id, settings: C.Settings }).strict(), ['連携設定を変更する', 'Change integration settings'],
    (who, input) => integrations.set(who, input.id, input.settings));
  bind({ name: 'settings.update', method: 'PUT', path: '/api/principals/:id/settings', schema: { params: C.IdParams,
    body: C.Settings, response: { 200: z.object({ settings: C.Settings }) } }, input: (params, body) => ({ id: params.id, settings: body }) });
}
