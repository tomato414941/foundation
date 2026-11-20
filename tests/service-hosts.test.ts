import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { MethodDefinition } from '../shared/contracts.js';
import { endpointTemplates, knownHosts, requireKnownHosts } from '../runtime/service-hosts.js';

const catalog = new URL('../server/catalog/', import.meta.url);
async function builtin(service: string, method: string) {
  const entry = JSON.parse(await readFile(new URL(service + '.json', catalog), 'utf8'));
  return entry.methods[method] as { name: string; kind: string; config: Record<string, unknown> };
}
const described = (method: { name: string; kind: string; config: Record<string, unknown> }, changes: Record<string, unknown>) =>
  MethodDefinition.parse({ name: method.name, kind: method.kind, config: { ...method.config, ...changes } });

test('組み込みの接続方法がトークンや鍵を送る先のホストを、CLIは送り先の表として持つ', async () => {
  const expected: Record<string, string[]> = {};
  for (const file of (await readdir(catalog)).filter(name => name.endsWith('.json')).sort()) {
    const entry = JSON.parse(await readFile(new URL(file, catalog), 'utf8')) as { id: string; methods?: Record<string, { config: unknown }> };
    for (const [key, method] of Object.entries(entry.methods ?? {})) {
      const hosts = [...new Set(endpointTemplates(method.config).map(template => /^https?:\/\/([^/?#]+)/.exec(template)?.[1])
        .filter((host): host is string => !!host))].sort();
      if (hosts.length) expected[entry.id + ':' + key] = hosts;
    }
  }
  assert.deepEqual(knownHosts, expected);
});

test('本番が組み込みの接続方法の送り先を別のホストに変えるとCLIは使わず、同じホストの別の道なら使う', async () => {
  const github = await builtin('github', 'oauth');
  requireKnownHosts('github:oauth', described(github, {}), {});
  requireKnownHosts('github:oauth', described(github, { tokenUrl: 'https://github.com/login/oauth/token' }), {});
  assert.throws(() => requireKnownHosts('github:oauth', described(github, { tokenUrl: 'https://tokens.example/oauth' }), {}),
    { code: 'unknown_service_host' });
  // A method Foundation's users made themselves is not known to the CLI and goes as Foundation describes it.
  requireKnownHosts(crypto.randomUUID(), described(github, { tokenUrl: 'https://tokens.example/oauth' }), {});
});

test('ホストの一部を接続の値で埋める方法は、封をした値で埋めたホストにだけ送る', async () => {
  const shopify = await builtin('shopify', 'oauth');
  requireKnownHosts('shopify:oauth', described(shopify, {}), { shop: 'mine' });
  assert.throws(() => requireKnownHosts('shopify:oauth', described(shopify, {
    tokenUrl: 'https://others.myshopify.com/admin/oauth/access_token' }), { shop: 'mine' }), { code: 'unknown_service_host' });
  assert.throws(() => requireKnownHosts('shopify:oauth', described(shopify, { defaults: { shop: 'others' } }), {}),
    { code: 'unknown_service_host' });
});
