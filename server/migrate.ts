import { configuration } from './config.js';
import { createContext } from './context.js';
import { Database } from './database.js';

const config = await configuration(), db = new Database(config.DATABASE_URL);
try {
  await createContext(config, { db }, { migrate: true });
  process.stdout.write('Database migrations applied.\n');
} finally { await db.close(); }
