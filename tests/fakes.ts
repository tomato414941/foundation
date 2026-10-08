import type { PaymentProvider, PaymentEvent } from '../server/billing.js';
import type { ObjectStore } from '../server/objects.js';
import type { Runner } from '../server/runner.js';
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
export class MemoryRunner implements Runner {
  readonly enabled = true;
  machines = new Map<string, { environment: Record<string, string>; options: EnvironmentOptions }>();
  volumes = new Set<string>();
  async start(
    id: string,
    options: EnvironmentOptions,
    environment: Record<string, string>,
    created: (id: string, volume: string) => Promise<void>,
  ) {
    this.machines.set(id, { environment, options });
    this.volumes.add('vol_' + id.replaceAll('-', ''));
    await created(id, 'vol_' + id.replaceAll('-', ''));
    return id;
  }
  async removeVolume(id: string) { this.volumes.delete(id); }
  async stop(id: string) {
    this.machines.delete(id);
  }
  async find(id: string) {
    return this.machines.has(id) ? id : null;
  }
  async findVolume(id: string) {
    const volume = 'vol_' + id.replaceAll('-', '');
    return this.volumes.has(volume) ? volume : null;
  }
}
