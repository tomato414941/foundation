import type { EnvironmentOptions } from '../shared/contracts.js';
import type { SSHKeyPair } from './ssh-client.js';

export interface MachineSSH { keys: SSHKeyPair; authorizedKeys: string[]; }

export interface Runner {
  readonly enabled: boolean;
  start(id: string, options: EnvironmentOptions, ssh: MachineSSH,
    created: (machineId: string, volumeId: string, host: string) => Promise<void>, networkSlot: number): Promise<string>;
  resume(machineId: string): Promise<{ volumeId: string; host: string }>;
  stop(machineId: string): Promise<void>;
  terminate(machineId: string): Promise<void>;
  find(id: string): Promise<string | null>;
  findVolume(id: string): Promise<string | null>;
  removeVolume(volumeId: string): Promise<void>;
  removeNetwork(id: string): Promise<void>;
}
