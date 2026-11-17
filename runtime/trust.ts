import type { Journal } from './journal.js';
import type { TrustStore } from '../shared/client.js';
import { hash, validateBinding } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { CustodyContent, CustodyPolicy } from '../shared/custody.js';

export class JournalTrust implements TrustStore {
  constructor(readonly journal: Journal) {}
  binding(principalId: string) { return this.journal.read<BoundKeys>('identity_' + principalId); }
  async bindings() {
    const bindings = await Promise.all((await this.journal.keys('identity_')).map(id => this.journal.read<BoundKeys>(id)));
    return bindings.filter(binding => binding !== null);
  }
  async rememberBinding(binding: BoundKeys) {
    await validateBinding(binding);
    await this.journal.write('identity_' + binding.principalId, binding);
  }
  keyring() { return this.journal.read<{ revision: number; digest: string }>('checkpoint_keyring'); }
  async rememberKeyring(seen: { revision: number; digest: string }) { await this.journal.write('checkpoint_keyring', seen); }
  checkpoint(content: CustodyContent) {
    return this.journal.read<{ policy: CustodyPolicy; materialRevision: number; digest: string }>(
      'checkpoint_' + content.policy.format + '_' + content.policy.id);
  }
  async rememberContent(content: CustodyContent) {
    await this.journal.write('checkpoint_' + content.policy.format + '_' + content.policy.id, {
      policy: content.policy, materialRevision: content.materialRevision, digest: await hash(content),
    });
  }
}
