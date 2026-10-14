import { z } from 'zod';
import * as C from '../../shared/contracts.js';
import { fail } from '../errors.js';

export const idInput = z.object({ id: C.Id }).strict();
export const bodyObject = (body: unknown) => C.JsonObject.parse(body);
export const withId = (params: Record<string, string>, body: unknown) => ({ ...bodyObject(body), id: params.id });
export const ok = () => ({ ok: true as const });

export const keyholder = async () => fail(400, 'keyholder_required', 'Continue this operation with your encryption keys.');
