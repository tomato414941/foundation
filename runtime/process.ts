import { z } from 'zod';
import type { JsonApi } from '../shared/client.js';
import { ClaimedProcess, ProcessView } from '../shared/process.js';
import type { Completion } from '../shared/process.js';
import type { CommandExecutor } from './command.js';
import type { Journal } from './journal.js';
import { DeliveryPending } from './executor.js';

export class ProcessBroker {
  constructor(readonly api: JsonApi) {}
  claim(id: string) {
    return this.api.json('/api/environments/' + id + '/processes/claim', { method: 'POST', body: {} }, ClaimedProcess);
  }
  dispatch(id: string, lease: string) {
    return this.api.json('/api/processes/' + id + '/dispatch', { method: 'POST', body: { lease } });
  }
  renew(id: string, lease: string) {
    return this.api.json('/api/processes/' + id + '/renew', { method: 'POST', body: { lease } }, z.object({ active: z.boolean() }));
  }
  finish(id: string, lease: string, completion: Completion) {
    return this.api.json('/api/processes/' + id + '/finish', { method: 'POST', body: { lease, ...completion } }, ProcessView);
  }
}
interface Record {
  id: string; lease: string; delivered: boolean; completion: Completion | null;
}
export class ProcessExecutor {
  constructor(readonly environmentId: string, readonly broker: ProcessBroker, readonly journal: Journal,
    readonly commands: CommandExecutor, readonly renewalMilliseconds = 15_000) {}

  private async deliver(record: Record) {
    await this.broker.finish(record.id, record.lease, record.completion!);
    await this.journal.write('process_' + record.id, { ...record, delivered: true });
  }
  async reconcile() {
    const pending: string[] = [];
    for (const key of await this.journal.keys('process_')) {
      const record = await this.journal.read<Record>(key);
      if (!record || record.delivered) continue;
      record.completion ??= { state: 'uncertain', result: null, error: 'execution_interrupted' };
      await this.journal.write(key, record);
      try { await this.deliver(record); } catch { pending.push(record.id); }
    }
    return pending;
  }
  async tick(signal: AbortSignal = new AbortController().signal) {
    signal.throwIfAborted();
    const claim = await this.broker.claim(this.environmentId);
    if (!claim) return false;
    const { lease, process } = claim;
    const previous = await this.journal.read<Record>('process_' + process.id);
    if (previous) {
      const completion = previous.completion ?? { state: 'uncertain' as const, result: null, error: 'execution_interrupted' };
      await this.broker.finish(process.id, lease, completion);
      return true;
    }
    const record: Record = { id: process.id, lease, delivered: false, completion: null };
    await this.journal.write('process_' + process.id, record);
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    let renewal: NodeJS.Timeout | undefined;
    try {
      await this.broker.dispatch(process.id, lease);
      renewal = setInterval(() => {
        void this.broker.renew(process.id, lease).then(value => { if (!value.active) abort(); }, abort);
      }, this.renewalMilliseconds);
      renewal.unref();
      const result = await this.commands.execute({ command: process.command, workingDirectory: process.workingDirectory,
        stdin: process.stdin, environment: process.environment, files: {}, timeoutSeconds: process.timeoutSeconds }, controller.signal);
      record.completion = { state: controller.signal.aborted ? 'cancelled' :
        result.exitCode === 0 && !result.timedOut ? 'succeeded' : 'failed', result, error: null };
    } catch {
      record.completion = { state: controller.signal.aborted ? 'cancelled' : 'failed', result: null, error: 'process_failed' };
    } finally {
      clearInterval(renewal);
      signal.removeEventListener('abort', abort);
    }
    await this.journal.write('process_' + process.id, record);
    try { await this.deliver(record); } catch { throw new DeliveryPending(); }
    return true;
  }
}
