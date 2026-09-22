import { validEnvName } from './env-name.mjs';

// What storage holds for one credential, and the only thing delivery reads.
//
// Acquisition builds this record and hands it over; storage seals it and gives it back
// unchanged. Storage never looks inside, so nothing here may depend on which service the
// credential belongs to:
//   environment  the values the command receives, already under the names it will read
//   files        values that must be a file while the command runs, each with the name of
//                the variable holding its path
//   session      a value the command receives as a tool's own login state, not as a variable
//   facts        what the owner is shown about it; never secret
//   renewal      what acquisition needs to check or refresh it later; storage passes it back
//                untouched and nothing else reads it
// expires_at is null when the value does not expire, and expiry_known is false when the
// service does not say.
export function held({ environment = {}, files = [], session = null, facts = {}, renewal = {}, expires_at = null, expiry_known = true, credential_type = 'api_key', scopes, verification }) {
  const names = [...Object.keys(environment), ...files.map(file => file.env)];
  for (const name of names) if (!validEnvName(name)) throw new Error('A credential cannot be delivered as ' + name);
  if (new Set(names).size !== names.length) throw new Error('A credential cannot deliver the same name twice');
  for (const value of Object.values(environment)) if (typeof value !== 'string') throw new Error('A delivered value must be a string');
  for (const file of files) if (typeof file.content !== 'string' || typeof file.filename !== 'string') throw new Error('A delivered file needs a filename and its content');
  return { environment, files, session, facts, renewal, expires_at, expiry_known, credential_type, ...(scopes ? { scopes } : {}), ...(verification ? { verification } : {}) };
}

// The names the command receives. Shown to the owner and to the key before any delivery.
export const names = record => [...Object.keys(record.environment), ...record.files.map(file => file.env)];

// What a command receives, taken from the record as it was stored.
export const delivery = record => ({ environment: record.environment, files: record.files, ...(record.session ? { expo_session: record.session } : {}) });
