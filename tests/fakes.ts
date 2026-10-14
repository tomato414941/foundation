import type { PaymentProvider, PaymentEvent } from '../server/billing.js';
import type { ObjectStore } from '../server/objects.js';
import type { MachineSSH, Runner } from '../server/runner.js';
import { OpenSSH } from '../server/ssh-client.js';
import type { SSHClient, SSHDestination } from '../server/ssh-client.js';
import type { EnvironmentOptions } from '../shared/contracts.js';

export class MemoryPayments implements PaymentProvider {
  readonly enabled = true;
  events: Array<{ id: string; amount: number }> = [];
  async customer(id: string) {
    return 'customer-' + id;
  }
  async checkout(id: string) {
    return 'https://pay.example/checkout/' + id;
  }
  async portal(id: string) {
    return 'https://pay.example/portal/' + id;
  }
  async event(body: Buffer, signature: string) {
    if (signature !== 'verified') throw new Error('Invalid signature');
    return JSON.parse(body.toString()) as PaymentEvent;
  }
  async meter(event: { id: string; amount: number }) {
    this.events.push(event);
  }
}
export class MemoryObjects implements ObjectStore {
  readonly enabled = true;
  files = new Map<string, Uint8Array>();
  async put(id: string, body: Uint8Array) {
    this.files.set(id, body.slice());
  }
  async get(id: string) {
    const value = this.files.get(id);
    if (!value) throw new Error('Missing object');
    return value.slice();
  }
  async remove(id: string) {
    this.files.delete(id);
  }
  async link(id: string, _name: string, seconds: number) {
    return 'https://objects.example/' + id + '?expires=' + seconds;
  }
  async publish(name: string, body: Uint8Array, _contentType: string, seconds: number) {
    this.files.set('published/' + name, body.slice());
    return 'https://objects.example/published/' + name + '?expires=' + seconds;
  }
}
export class MemorySSH implements SSHClient {
  sessions = new Map<string, number>();
  unavailable = new Set<string>();
  configurations = new Map<string, string>();
  keys() { return new OpenSSH().keys(); }
  async run(destination: SSHDestination, _command: string, input?: string) {
    if (this.unavailable.has(destination.id)) throw new Error('SSH unavailable');
    this.configurations.set(destination.id, input ?? '');
    return { code: 0, stdout: String((this.sessions.get(destination.id) ?? 0) + 1) + '\n', stderr: '' };
  }
}
export class MemoryRunner implements Runner {
  readonly enabled = true;
  readonly ssh = new MemorySSH();
  machines = new Map<string, { ssh: MachineSSH; options: EnvironmentOptions; state: 'running' | 'stopped' }>();
  volumes = new Set<string>();
  networks = new Set<string>();
  async start(
    id: string,
    options: EnvironmentOptions,
    ssh: MachineSSH,
    created: (id: string, volume: string, host: string) => Promise<void>,
  ) {
    this.networks.add(id);
    this.machines.set(id, { ssh, options, state: 'running' });
    this.volumes.add('vol_' + id.replaceAll('-', ''));
    await created(id, 'vol_' + id.replaceAll('-', ''), id + '.ssh.foundation.test');
    return id;
  }
  async removeVolume(id: string) { this.volumes.delete(id); }
  async resume(id: string) {
    const machine = this.machines.get(id);
    if (!machine) throw new Error('Missing environment');
    machine.state = 'running';
    return { volumeId: 'vol_' + id.replaceAll('-', ''), host: id + '.restarted.ssh.foundation.test' };
  }
  async stop(id: string) {
    const machine = this.machines.get(id);
    if (machine) machine.state = 'stopped';
  }
  async terminate(id: string) { this.machines.delete(id); }
  async removeNetwork(id: string) { this.networks.delete(id); }
  async find(id: string) {
    return this.machines.has(id) ? id : null;
  }
  async findVolume(id: string) {
    const volume = 'vol_' + id.replaceAll('-', '');
    return this.volumes.has(volume) ? volume : null;
  }
}
