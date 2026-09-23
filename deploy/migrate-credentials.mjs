// A one-off: carries what an older database kept into the store this version uses.
//
// Before storage became one thing, a connected service lived in a `credentials` row whose secret was sealed
// against `credential:<owner>:<id>`. Now the same connection is an acquisition plus the entries it owns,
// sealed against different bindings and under a different data key. Nothing can be copied across; each
// secret is opened with the old key and written again through the code that writes them today.
//
//   node deploy/migrate-credentials.mjs <old-database> [--commit]
//
// Without --commit it only reports what it would do. Approved keys come across as they are: the agents
// table did not change, so a key its owner already approved keeps working.
import { DatabaseSync } from 'node:sqlite';
import { configuration } from '../src/config.mjs';
import { Vault } from '../src/crypto.mjs';
import { Kms } from '../src/kms.mjs';
import { Store } from '../src/store.mjs';
import { Adapters } from '../src/adapters.mjs';
import { Acquisitions } from '../src/acquisitions.mjs';
import { GmailClient } from '../src/services/gmail.mjs';
import { OpenRouterClient } from '../src/services/openrouter.mjs';
import { ExpoClient } from '../src/services/expo.mjs';
import { GitHubClient } from '../src/services/github.mjs';
import { gmailReadonly, gmailMetadata, openrouterOauth, expoLogin, githubOauth } from '../src/adapters.mjs';

const [oldPath, ...flags] = process.argv.slice(2);
if (!oldPath) throw new Error('Usage: node deploy/migrate-credentials.mjs <old-database> [--commit]');
const commit = flags.includes('--commit');
const config = configuration();
const kms = config.kms.keyId ? new Kms({ keyId: config.kms.keyId, region: config.kms.region }) : null;

// The old database carries its own wrapped key; the new one carries another.
const old = new DatabaseSync(oldPath, { readOnly: true });
const wrapped = old.prepare("SELECT value FROM metadata WHERE name='wrapped_key'").get()?.value;
if (!wrapped && !config.encryptionKey) throw new Error('The old database has no wrapped key and no plaintext key was given.');
const oldKey = wrapped ? await kms.unwrap(wrapped) : config.encryptionKey;
const oldVault = new Vault(oldKey);

const gmail = new GmailClient(config.google), expo = new ExpoClient(config.expo), github = new GitHubClient(config.github);
const adapters = new Adapters([githubOauth(github), openrouterOauth(new OpenRouterClient()), expoLogin(expo), gmailReadonly(gmail), gmailMetadata(gmail)]);
const store = new Store(config.database, await resolveNewKey());
const acquisitions = new Acquisitions(store, adapters);

async function resolveNewKey() {
  const fresh = new DatabaseSync(config.database, { readOnly: true });
  const row = fresh.prepare("SELECT value FROM metadata WHERE name='wrapped_key'").get();
  fresh.close();
  if (row) return kms.unwrap(row.value);
  if (config.encryptionKey) return config.encryptionKey;
  throw new Error('The current database has no key this process can use.');
}

const report = [];
for (const row of old.prepare('SELECT * FROM credentials ORDER BY created_at').all()) {
  let secret;
  try { secret = oldVault.open(row.secret, `credential:${row.owner_id}:${row.id}`); }
  catch (error) { report.push([row.adapter, row.subject, 'unreadable: ' + error.message]); continue; }
  if (!adapters.ids().includes(row.adapter)) { report.push([row.adapter, row.subject, 'no such adapter any more']); continue; }
  if (row.status !== 'connected') { report.push([row.adapter, row.subject, 'not connected (' + row.status + ')']); continue; }
  if (!commit) { report.push([row.adapter, row.subject, 'would move']); continue; }
  try {
    const previous = store.acquisitions(row.owner_id).find(item => item.adapter === row.adapter && item.subject === row.subject);
    acquisitions.save(row.owner_id, row.adapter, { subject: row.subject, secret }, { keptBy: row.requested_by || '', previous });
    report.push([row.adapter, row.subject, 'moved']);
  } catch (error) { report.push([row.adapter, row.subject, 'failed: ' + error.message]); }
}

// An approved key is the same row in both schemas, so it comes across untouched.
let keys = 0;
for (const agent of old.prepare('SELECT * FROM agents').all()) {
  if (store.db.prepare('SELECT 1 FROM agents WHERE token_hash=?').get(agent.token_hash)) continue;
  if (!commit) { keys++; continue; }
  store.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at,last_used_at,issued_until,issued_nonexpiring) VALUES (?,?,?,?,?,?,?,?)')
    .run(agent.id, agent.owner_id, agent.name, agent.token_hash, agent.created_at, agent.last_used_at, agent.issued_until, agent.issued_nonexpiring);
  keys++;
}

for (const [adapter, subject, what] of report) console.log([adapter, subject, what].join('\t'));
console.log(`keys: ${keys}${commit ? ' carried over' : ' would be carried over'}`);
console.log(commit ? 'committed' : 'nothing written; pass --commit to write');
old.close();
store.close();
