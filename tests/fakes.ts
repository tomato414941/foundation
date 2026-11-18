import type { PaymentProvider, PaymentEvent } from '../server/billing.js';
import type { ObjectStore } from '../server/objects.js';

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
  objects = new Map<string, Uint8Array>();
  async put(id: string, body: Uint8Array) {
    this.objects.set(id, body.slice());
  }
  async get(id: string) {
    const value = this.objects.get(id);
    if (!value) throw new Error('Missing object');
    return value.slice();
  }
  async remove(id: string) {
    this.objects.delete(id);
  }
  async link(id: string, _name: string, seconds: number) {
    return 'https://files.example/' + id + '?expires=' + seconds;
  }
}
