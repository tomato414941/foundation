import type { Journal } from './journal.js';
import type { TrustStore } from '../shared/client.js';
import { canonical, hash, validateBinding } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { CustodyContent, CustodyPolicy, SealedRun } from '../shared/custody.js';

export class JournalTrust implements TrustStore {
  constructor(readonly journal: Journal) {}
  binding(principalId: string) { return this.journal.read<BoundKeys>('identity_' + principalId); }
  async rememberBinding(binding: BoundKeys) {
    await validateBinding(binding);
    await this.journal.write('identity_' + binding.principalId, binding);
  }
  checkpoint(id: string) {
    return this.journal.read<{ policy: CustodyPolicy; materialRevision: number; digest: string }>('checkpoint_' + id);
  }
  async rememberContent(content: CustodyContent) {
    await this.journal.write('checkpoint_' + content.policy.id, {
      policy: content.policy, materialRevision: content.materialRevision, digest: await hash(content),
    });
  }
  run(id: string) { return this.journal.read<SealedRun>('run_' + id); }
  async rememberRun(request: SealedRun) {
    const previous = await this.run(request.intent.id);
    if (previous && canonical(previous) !== canonical(request)) throw new Error('Use a new execution ID for a different request.');
    await this.journal.write('run_' + request.intent.id, request);
  }
}
