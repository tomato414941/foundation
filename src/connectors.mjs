import { fail } from './errors.mjs';
import { appFieldsOf, takesApps } from './apps.mjs';

// A connector supplies authorization, obtains credentials, and may support revocation.
// It sees values only: { subject, privateState }, never a database row or storage handle.
// Results separate encrypted privateState, public facts, and deliverable credentials.
export class Connectors {
  constructor(connectors) {
    this.connectors = new Map();
    for (const connector of connectors) {
      if (!connector || typeof connector.id !== 'string' || !/^[a-z][a-z0-9.-]{0,63}$/.test(connector.id) || this.connectors.has(connector.id)) throw new Error('Invalid or duplicate connector ID');
      if (!Array.isArray(connector.variables) || new Set(connector.variables).size !== connector.variables.length
        || connector.variables.some(value => typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value))
        || !['oauth', 'role'].includes(connector.authorization?.kind) || typeof connector.obtain !== 'function' || typeof connector.authorization?.begin !== 'function'
        || typeof connector.authorization?.complete !== 'function'
        || (connector.authorization.changes !== undefined && typeof connector.authorization.changes !== 'function')
        || (connector.revoke !== undefined && typeof connector.revoke !== 'function')
        || (connector.scopes !== undefined && (connector.authorization.kind !== 'oauth' || !Array.isArray(connector.scopes.base)
          || connector.scopes.base.some(scope => typeof scope !== 'string' || !scope)))) throw new Error('Invalid connector contract: ' + connector.id);
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
    return { id, flow: connector.authorization.kind, service: connector.service, label: connector.label, register: connector.register, available: connector.available,
      intro: connector.intro || '', access: connector.access, variables: connector.variables,
      ...(connector.ai ? { ai: connector.ai } : {}), ...(connector.failureNote ? { failure_note: connector.failureNote } : {}),
      ...(connector.revocationNote ? { revocation_note: connector.revocationNote } : {}),
      can_reconnect: connector.canReconnect !== false, can_revoke: typeof connector.revoke === 'function', credential_type: connector.credentialType || 'unknown',
      scopes: connector.scopes ? { base: connector.scopes.base, documentation_url: connector.scopes.documentationUrl || '' } : null,
      // Whether the service is authorized through apps: what registering one asks for, and whether Foundation offers
      // its own. available says whether Foundation's own side is set up (its app, or for a role, its role).
      // A connector that knows services only through their apps (generic OAuth 2.0) names each service by its app.
      apps: takesApps(connector) ? { fields: appFieldsOf(connector).map(({ check, leading, ...field }) => field), foundation: Boolean(connector.oauthClient.enabled),
        service_from_app: typeof connector.serviceFor === 'function' } : null };
  }
}
