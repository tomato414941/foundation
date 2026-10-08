import type { EnvironmentOptions } from '../shared/contracts.js';
import type { Configuration } from './config.js';
import { DomainError, fail } from './errors.js';

export interface Runner {
  readonly enabled: boolean;
  start(id: string, options: EnvironmentOptions, environment: Record<string, string>,
    created: (machineId: string, volumeId: string) => Promise<void>): Promise<string>;
  stop(machineId: string): Promise<void>;
  find(id: string): Promise<string | null>;
  removeVolume(volumeId: string): Promise<void>;
}
const sizes = {
  small: { cpu_kind: 'shared', cpus: 1, memory_mb: 1024 },
  medium: { cpu_kind: 'shared', cpus: 2, memory_mb: 2048 },
  large: { cpu_kind: 'shared', cpus: 4, memory_mb: 4096 },
};
type Row = Record<string, unknown>;
export class FlyRunner implements Runner {
  readonly enabled: boolean;
  constructor(readonly config: Configuration) {
    this.enabled = Boolean(config.FLY_API_TOKEN && config.FLY_APP &&
      /^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(config.FLY_IMAGE));
  }
  private async call(method: string, path: string, body?: unknown): Promise<Row | Row[]> {
    if (!this.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    try {
      const response = await fetch(
        'https://api.machines.dev/v1/apps/' + encodeURIComponent(this.config.FLY_APP) + path,
        { method, headers: { authorization: 'Bearer ' + this.config.FLY_API_TOKEN,
            ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
          redirect: 'error', signal: AbortSignal.timeout(30_000),
          ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      if (response.status === 404) throw new DomainError(404, 'machine_missing', 'The environment was not found.');
      if (!response.ok) fail(502, 'runner_unavailable', 'The environment provider could not complete the operation.');
      const text = await response.text();
      if (text.length > 4_000_000) fail(502, 'runner_response', 'The environment provider returned too much data.');
      return text ? JSON.parse(text) : {};
    } catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'runner_unavailable', 'The environment provider could not be reached.');
    }
  }
  async find(id: string) {
    const rows = await this.call('GET', '/machines');
    if (!Array.isArray(rows)) fail(502, 'runner_response', 'The environment provider returned an invalid response.');
    return (rows.find(row => row.name === 'foundation-' + id)?.id as string | undefined) ?? null;
  }
  private async volume(id: string, options: EnvironmentOptions) {
    const name = 'f_' + id.replaceAll('-', '').slice(0, 28);
    const list = async () => {
      const rows = await this.call('GET', '/volumes');
      if (!Array.isArray(rows)) fail(502, 'runner_response', 'The environment provider returned an invalid response.');
      const matches = rows.filter(row => row.name === name && row.state !== 'destroyed');
      if (matches.length > 1) fail(409, 'volume_ambiguous', 'Resolve duplicate executor volumes before continuing.');
      return matches[0];
    };
    let volume = await list();
    if (!volume) {
      try {
        const created = await this.call('POST', '/volumes', { name, region: this.config.FLY_REGION,
          size_gb: 3, encrypted: true, auto_backup_enabled: true, compute: sizes[options.size] });
        if (Array.isArray(created)) fail(502, 'runner_response', 'The environment provider returned an invalid response.');
        volume = created;
      } catch (error) {
        volume = await list();
        if (!volume) throw error;
      }
    }
    if (typeof volume.id !== 'string') fail(502, 'runner_response', 'The executor volume could not be identified.');
    return volume.id;
  }
  async start(id: string, options: EnvironmentOptions, environment: Record<string, string>,
    created: (machineId: string, volumeId: string) => Promise<void>) {
    const volumeId = await this.volume(id, options);
    let machineId = await this.find(id);
    if (!machineId) {
      try {
        const machine = await this.call('POST', '/machines', { name: 'foundation-' + id,
          region: this.config.FLY_REGION, config: {
            image: this.config.FLY_IMAGE, env: { ...environment, XDG_CONFIG_HOME: '/data/config' },
            guest: sizes[options.size], mounts: [{ volume: volumeId, path: '/data' }],
            auto_destroy: false, restart: { policy: 'on-failure', max_retries: 3 },
            metadata: { foundation_environment: id },
          } });
        if (Array.isArray(machine) || typeof machine.id !== 'string')
          fail(502, 'runner_response', 'The environment provider returned an invalid response.');
        machineId = machine.id;
      } catch (error) {
        machineId = await this.find(id);
        if (!machineId) throw error;
      }
    }
    await created(machineId, volumeId);
    return machineId;
  }
  async stop(machineId: string) {
    try { await this.call('DELETE', '/machines/' + encodeURIComponent(machineId) + '?force=true'); }
    catch (error) { if (!(error instanceof DomainError && error.code === 'machine_missing')) throw error; }
  }
  async removeVolume(volumeId: string) {
    if (!/^vol_[a-zA-Z0-9]+$/.test(volumeId)) throw new Error('Use a resolved executor volume ID.');
    try { await this.call('DELETE', '/volumes/' + encodeURIComponent(volumeId)); }
    catch (error) { if (!(error instanceof DomainError && error.code === 'machine_missing')) throw error; }
  }
}
