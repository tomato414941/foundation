import { z } from 'zod';
import { fail } from './errors.js';
import { responseJson } from './http.js';
import type { Transport } from './http.js';

export const RunPodApproval = z.object({ id: z.string().min(1).max(1000),
  expiresAt: z.number().int().positive() }).strict();
export type RunPodApprovalState = z.infer<typeof RunPodApproval>;

async function graphql(transport: Transport, query: string, variables = {}) {
  const response = await transport.send({ url: 'https://api.runpod.io/graphql', method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query, variables }) });
  if (response.status >= 400) fail(502, 'authorization_failed', 'RunPod could not authorize this connection.');
  const data = responseJson(response);
  if (data.errors) fail(502, 'authorization_failed', 'RunPod could not authorize this connection.');
  return z.record(z.string(), z.unknown()).parse(data.data);
}
export async function startRunPodApproval(transport: Transport) {
  const response = await graphql(transport, `mutation createFlashAuthRequest {
    createFlashAuthRequest { id status expiresAt }
  }`);
  const request = z.object({ id: z.string().min(1).max(1000), expiresAt: z.iso.datetime({ offset: true }) })
    .parse(response.createFlashAuthRequest);
  const approval = RunPodApproval.parse({ id: request.id, expiresAt: Date.parse(request.expiresAt) });
  if (approval.expiresAt <= Date.now()) fail(409, 'authorization_expired', 'Start the RunPod connection again.');
  const url = new URL('https://console.runpod.io/flash/login');
  url.searchParams.set('request', request.id);
  return { approval, url: url.href };
}
export async function pollRunPodApproval(transport: Transport, approval: RunPodApprovalState) {
  if (approval.expiresAt <= Date.now()) fail(409, 'authorization_expired', 'Start the RunPod connection again.');
  const response = await graphql(transport, `query flashAuthRequestStatus($flashAuthRequestId: String!) {
    flashAuthRequestStatus(flashAuthRequestId: $flashAuthRequestId) { id status expiresAt apiKey }
  }`, { flashAuthRequestId: approval.id });
  const request = z.object({ id: z.string(), status: z.string(), apiKey: z.string().nullish() })
    .parse(response.flashAuthRequestStatus);
  if (request.id !== approval.id) fail(502, 'invalid_response', 'RunPod returned another authorization request.');
  if (request.apiKey && ['APPROVED', 'CONSUMED'].includes(request.status))
    return z.string().min(1).max(16384).regex(/^\S+$/).parse(request.apiKey);
  if (['DENIED', 'EXPIRED', 'CONSUMED'].includes(request.status))
    fail(409, 'authorization_failed', 'Start the RunPod connection again.');
  if (request.status !== 'PENDING') fail(502, 'invalid_response', 'RunPod returned an unknown authorization state.');
  return null;
}
