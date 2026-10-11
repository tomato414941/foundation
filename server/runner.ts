import type { EnvironmentOptions } from '../shared/contracts.js';

export interface Runner {
  readonly enabled: boolean;
  start(id: string, options: EnvironmentOptions, environment: Record<string, string>,
    created: (machineId: string, volumeId: string, host: string) => Promise<void>, networkSlot: number): Promise<string>;
  stop(machineId: string): Promise<void>;
  terminate(machineId: string): Promise<void>;
  find(id: string): Promise<string | null>;
  findVolume(id: string): Promise<string | null>;
  removeVolume(volumeId: string): Promise<void>;
  removeNetwork(id: string): Promise<void>;
}
