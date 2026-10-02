import { randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';

// A name for a principal that began with nothing but a passkey: a role at a star, drawn at random, so that two
// such principals on one device are told apart in its passkey list before either has been named. The stars are
// the IAU Catalog of Star Names (data/IAU-CSN.txt, the Working Group on Star Names' list, by its ASCII names);
// the roles are a short list of occupations. The name can be changed any time.
export const STARS = readFileSync(new URL('./data/IAU-CSN.txt', import.meta.url), 'utf8').split('\n')
  .filter(line => line && !line.startsWith('#') && !line.startsWith('$')).map(line => line.slice(0, 18).trim()).filter(Boolean);
export const ROLES = ['Navigator', 'Cartographer', 'Astronomer', 'Surveyor', 'Archivist', 'Librarian', 'Curator', 'Engineer', 'Pilot', 'Envoy',
  'Consul', 'Steward', 'Warden', 'Ranger', 'Scout', 'Keeper', 'Herald', 'Registrar', 'Chancellor', 'Observer', 'Lighthouse Keeper', 'Harbormaster',
  'Geologist', 'Botanist', 'Meteorologist', 'Physician', 'Chronicler', 'Interpreter', 'Quartermaster', 'Signalman'];

export const principalName = () => ROLES[randomInt(ROLES.length)] + ' ' + STARS[randomInt(STARS.length)];
