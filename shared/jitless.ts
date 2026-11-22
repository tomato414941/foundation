import { z } from 'zod';

// A browser runs under a content security policy that allows no eval, so zod checks values there without compiling
// checks of its own. Modules that define schemas before anything else load import this first.
if (typeof window !== 'undefined') z.config({ jitless: true });
