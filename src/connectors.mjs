import { fail } from './errors.mjs';

// A connector supplies authorization, obtains credentials, and may support revocation.
// It sees values only: { subject, privateState }, never a database row or storage handle.
// Results separate encrypted privateState, public facts, and deliverable credentials.
export class Connectors {
  constructor(connectors) {
    this.connectors = new Map();
    for (const connector of connectors) {
      if (!connector || typeof connector.id !== 'string' || !/^[a-z][a-z0-9.-]{0,63}$/.test(connector.id) || this.connectors.has(connector.id)) throw new Error('Invalid or duplicate connector ID');
      if (connector.provider !== undefined && !/^[a-z][a-z0-9-]{0,39}$/.test(connector.provider)) throw new Error('Invalid connector provider: ' + connector.id);
      if (!Array.isArray(connector.variables) || new Set(connector.variables).size !== connector.variables.length
        || connector.variables.some(value => typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value))
        || typeof connector.obtain !== 'function' || typeof connector.authorization?.begin !== 'function'
        || typeof connector.authorization?.complete !== 'function'
        || (connector.revoke !== undefined && typeof connector.revoke !== 'function')) throw new Error('Invalid connector contract: ' + connector.id);
      this.connectors.set(connector.id, connector);
    }
  }
  get(id) {
    const connector = typeof id === 'string' && this.connectors.get(id);
    if (!connector) fail(400, 'invalid_connector', '対応している接続方法を指定してください。');
    return connector;
  }
  ids() { return [...this.connectors.keys()]; }
  describe(id) {
    const connector = this.get(id);
    return { id, provider: connector.provider ?? id.split('.')[0], service: connector.service, label: connector.label, register: connector.register, available: connector.available,
      intro: connector.intro || '', access: connector.access, variables: connector.variables,
      ...(connector.ai ? { ai: connector.ai } : {}), ...(connector.kind ? { kind: connector.kind } : {}), ...(connector.failureNote ? { failure_note: connector.failureNote } : {}),
      ...(connector.revocationNote ? { revocation_note: connector.revocationNote } : {}),
      can_reconnect: connector.canReconnect !== false, can_revoke: typeof connector.revoke === 'function', credential_type: connector.credentialType || 'unknown' };
  }
}
