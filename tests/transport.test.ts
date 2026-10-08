import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { publicAddress, publicUrl, PublicTransport } from '../server/transport.js';

const specialAddresses = [
  '0.0.0.0', '10.1.1.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
  '172.16.1.1', '192.0.0.1', '192.0.2.1', '192.88.99.1', '192.168.1.1',
  '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255',
  '::', '::1', '::ffff:127.0.0.1', '::ffff:8.8.8.8', '64:ff9b::a00:1', '64:ff9b:1::1',
  '100::1', '2001::1', '2001:2::1', '2001:0002:0000:ffff:ffff:ffff:ffff:ffff',
  '2001:10::1', '2001:db8::1', '2002::1', '3fff::1', '3FFF:0FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
  '5f00::1', 'fc00::1', 'fe80::1', 'fec0::1', 'ff02::1', '4000::1',
];

test('通常の公開IPと到達可能な特殊用途の範囲を許可する', () => {
  for (const address of [
    '8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2a00:1450:4001::1',
    '192.52.193.1', '192.175.48.1', '192.31.196.1', '2001:3::1',
    '2001:4:112::1', '2620:4f:8000::1', '2001:20::1', '2001:30::1',
  ]) {
    assert.equal(publicAddress(address), true, address);
    const host = address.includes(':') ? `[${address}]` : address;
    assert.equal(publicUrl(`https://${host}/path`).pathname, '/path', address);
  }
});

test('内部用・文書用・試験用のIPをURLの送信先として拒否する', async () => {
  const transport = new PublicTransport('https://foundation.test');
  for (const address of specialAddresses) {
    assert.equal(publicAddress(address), false, address);
    const host = address.includes(':') ? `[${address}]` : address;
    const url = `https://${host}/path`;
    assert.throws(() => publicUrl(url), { code: 'private_destination' }, address);
    await assert.rejects(transport.send({ url }), { code: 'private_destination' }, address);
  }
  for (const address of ['not-an-ip', '127.1', '0x7f000001', '999.0.0.1', '2606:4700::1%eth0'])
    assert.equal(publicAddress(address), false, address);
});

test('DNSの回答に許可しないIPが含まれる場合は接続前に送信を拒否する', async (t) => {
  let records: Array<{ address: string; family: number }> = [];
  let connections = 0;
  t.mock.method(dns, 'lookup', async () => records);
  t.mock.method(https, 'request', () => { connections++; throw new Error('Unexpected connection'); });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  const transport = new PublicTransport('https://foundation.test');
  for (const address of specialAddresses) {
    const forbidden = { address, family: address.includes(':') ? 6 : 4 };
    for (const answer of [[forbidden], [{ address: '8.8.8.8', family: 4 }, forbidden]]) {
      records = answer;
      await assert.rejects(transport.send({ url: 'https://destination.example/path' }),
        { code: 'private_destination' }, address);
    }
  }
  records = [];
  await assert.rejects(transport.send({ url: 'https://destination.example/path' }), { code: 'private_destination' });
  assert.equal(connections, 0);
});
