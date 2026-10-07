import type { Journal } from './journal.js';
import type { TrustStore } from '../shared/client.js';
import { hash, validateBinding } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { CustodyContent, CustodyPolicy } from '../shared/custody.js';

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
}
