import { Template } from '@fedify/uri-template';
import { createHash } from 'node:crypto';
import type { z } from 'zod';
import type { OAuthDefinition } from '../shared/contracts.js';
import { publicUrl } from './transport.js';
import { fail } from './errors.js';

export type OAuthSpec = z.infer<typeof OAuthDefinition>;
export interface OAuthApp {
  clientId: string;
  clientSecret?: string;
  fields: Record<string, string>;
  version?: number;
}
export interface OAuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number | null;
  refreshExpiresAt?: number;
  scopes: string[];
  requestedScopes?: string[];
  account: string;
  accountName: string;
  accountVerified?: boolean;
  scopesStatus?: 'unknown' | 'requested' | 'reported';
  extra: Record<string, string>;
  facts: Record<string, unknown>;
}
export type TokenCheckpoint = (token: OAuthToken, response: Record<string, unknown>) => Promise<void>;
export function expandUrl(template: string, values: Record<string, string>): string {
  try {
    return publicUrl(new Template(template).expand(values)).href;
  } catch {
    fail(400, 'invalid_service_url', 'Check the service URL and its required fields.');
  }
}
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export const strings = (value: unknown, separator = ' ') =>
  typeof value === 'string' ? [...new Set(value.split(separator).filter(Boolean))].sort() : [];
export const lifetime = (value: unknown) => {
  const seconds = typeof value === 'number' || typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isSafeInteger(seconds) || seconds <= 0 || seconds > 315_576_000)
    fail(502, 'invalid_response', 'The service returned an invalid expiry.');
  return seconds;
};
