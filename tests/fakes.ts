import type { ObjectStore } from '../server/objects.js';

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
