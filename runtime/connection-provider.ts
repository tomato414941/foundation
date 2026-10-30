import type { AppState, ConnectionState } from '../shared/connections.js';
import type { ConnectionFactValues } from '../shared/connection-facts.js';

export type ConnectionCheckpoint = Record<string, unknown>;
// A connection's outputs, with those its method delivers as files.
export interface ConnectionOutputs { values: Record<string, string>; files: string[] }
export interface RenewalContext {
  material: ConnectionState;
  app: AppState | null;
  signal: AbortSignal;
  receive(checkpoint: ConnectionCheckpoint): Promise<void>;
}
export interface ConnectionProvider {
  facts(material: ConnectionState): ConnectionFactValues;
  needsRenewal(material: ConnectionState): boolean;
  renew?(context: RenewalContext): Promise<ConnectionState>;
  recover?(material: ConnectionState, app: AppState | null, checkpoint: ConnectionCheckpoint): Promise<ConnectionState>;
  outputs(material: ConnectionState, app: AppState | null, signal: AbortSignal): Promise<Record<string, string>>;
  revoke?(material: ConnectionState, app: AppState | null, signal: AbortSignal): Promise<void>;
}
