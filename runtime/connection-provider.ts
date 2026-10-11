import type { AppState, ConnectionCommand, ConnectionState } from '../shared/connections.js';

export type ConnectionStart = Extract<ConnectionCommand, { action: 'start' }>;
export type ConnectionCheckpoint = Record<string, unknown>;
export interface AuthorizationContext {
  input: ConnectionStart;
  app: AppState | null;
  state: string;
  verifier: string;
  signal: AbortSignal;
  dispatch(): Promise<void>;
  receive(checkpoint: ConnectionCheckpoint): Promise<void>;
}
export interface RenewalContext {
  material: ConnectionState;
  app: AppState | null;
  signal: AbortSignal;
  receive(checkpoint: ConnectionCheckpoint): Promise<void>;
}
export type AuthorizationResult = { kind: 'authorize'; url: string }
  | { kind: 'ready'; material: ConnectionState };

// Providers handle authentication. Custody, approvals, journaling, and delivery belong to Connections.
export interface ConnectionProvider {
  validate(input: ConnectionStart, app: AppState | null): void;
  start(context: AuthorizationContext): Promise<AuthorizationResult>;
  exchange?(context: AuthorizationContext, parameters: string, checkpoint?: ConnectionCheckpoint): Promise<ConnectionState>;
  needsRenewal(material: ConnectionState): boolean;
  renew?(context: RenewalContext): Promise<ConnectionState>;
  recover?(material: ConnectionState, app: AppState | null, checkpoint: ConnectionCheckpoint): Promise<ConnectionState>;
  check?(material: ConnectionState, signal: AbortSignal): Promise<void>;
  outputs(material: ConnectionState, app: AppState | null, signal: AbortSignal): Promise<Record<string, string>>;
  revoke?(material: ConnectionState, app: AppState | null, signal: AbortSignal): Promise<void>;
}
