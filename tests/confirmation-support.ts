import type { InjectOptions, LightMyRequestResponse } from 'fastify';
import type { Actor } from '../server/authorization.js';
import type { Confirmations } from '../server/confirmations.js';
import type { IdentityKeys } from '../shared/authority.js';
import { signConfirmation } from '../shared/confirmations.js';
import type { ConfirmationOperation, ConfirmationView } from '../shared/confirmations.js';

type App = { inject(options: InjectOptions): Promise<LightMyRequestResponse> };

// Sends a call and, when the change takes a confirmation, confirms it by signing with the caller's keys and sends it
// again, as the CLI does.
export async function confirmedCall(app: App, keys: IdentityKeys, request: InjectOptions & { headers: Record<string, string> }) {
  const first = await app.inject(request);
  if (first.statusCode !== 403 || first.json().error?.code !== 'confirmation_required') return first;
  const headers = request.headers;
  const view = (await app.inject({ method: 'POST', url: '/api/confirmations', headers,
    payload: { operation: first.json().error.details.operation } })).json() as ConfirmationView;
  const proved = await app.inject({ method: 'POST', url: '/api/confirmations/' + view.id + '/proof', headers,
    payload: { method: 'signature', signature: await signConfirmation(view, keys.signing) } });
  if (proved.statusCode !== 200) throw new Error(proved.body);
  return app.inject({ ...request, headers: { ...headers, 'foundation-confirmation': view.id } });
}

// The actor carrying a confirmation of the change, signed with its keys, for calling a service directly.
export async function confirmedActor(confirmations: Confirmations, actor: Actor, keys: IdentityKeys, operation: ConfirmationOperation) {
  const view = await confirmations.start(actor, operation);
  await confirmations.prove(actor, view.id, { method: 'signature', signature: await signConfirmation(view, keys.signing) });
  return { ...actor, confirmation: view.id };
}
