// Printed by `foundation --help`. Written for an AI agent that has just been told to use an
// external service and needs the whole procedure in one read. What each adapter is, receives
// and delivers comes from the server's own adapter list; nothing about a service is written here.
// This text is read by the agent, not by the owner, so it is English; everything the owner reads
// (purposes, guidance, the dashboard) stays in the owner's language.
function adapterLines(adapters) {
  if (!adapters) return ['   Run `foundation adapters` for the available adapters and what each one is (needs FOUNDATION_URL).'];
  const lines = [];
  for (const adapter of adapters.filter(item => item.available)) {
    const service = adapter.service?.name || 'service declared on the request';
    lines.push('   ' + adapter.id + '  ' + service + ' / ' + adapter.access.name + (adapter.variables.length ? '  delivers: ' + adapter.variables.join(', ') : ''));
    lines.push('     foundation connect --adapter ' + adapter.id + ' --purpose "<purpose>"' + (adapter.declared ? '   (add the declaration described below)' : ''));
    if (adapter.ai) lines.push('     ' + adapter.ai);
  }
  const unavailable = adapters.filter(item => !item.available);
  if (unavailable.length) lines.push('   Currently unavailable: ' + unavailable.map(item => item.id).join(', '));
  return lines;
}

export function guide(adapters) {
  return ['Foundation keeps what belongs to the owner, under the owner\'s control. Two things live here, and either one works without the other.',
    '  Acquisition: obtain a credential for an external service with the owner\'s approval, and hand it to a command as environment variables (steps 1-5).',
    '  Storage: keep anything you obtained or wrote yourself, and have it back, or handed to a command, later (see STORAGE). An approved key may use it at any time, with no request.',
    'Never ask the owner to paste a key or token into the chat. It goes through Foundation.', '',
    'Terms: credential = one thing the owner handed to Foundation. adapter = the kind it is, which decides how it is received, checked and delivered. service = a name the credential is grouped under, chosen by the owner.',
    'Your standing: you hold one access key. Once the owner approves it, you may use every credential they keep, and all of storage (same as being logged in to gh or aws).',
    '  `foundation whoami` tells you your key\'s name (401 not_approved if it is not approved yet).',
    '',
    'ACQUISITION',
    '1. Approval (first time only). If `foundation whoami` returns 401 not_approved, the key is not approved yet.',
    '   Run `foundation connect` (no options; --name to change the name) and give the owner the verification_uri and the confirmation_code from the output.',
    '   Always show the code: the owner types it by hand. They open the URL and approve. This request registers no credential.',
    '   Retry `foundation whoami` every few seconds until it passes, then go to 2. Do not hammer it.',
    '2. If `foundation credentials` already has what you need, skip to 4. Otherwise ask for a registration. Choose an adapter:',
    ...adapterLines(adapters),
    '   foundation connect --adapter <adapter> --purpose "<purpose>" [--guide "<instructions>"] [--valid <minutes>]   Give the owner the verification_uri from the output (there is no code).',
    '   Write the purpose as one concrete sentence the owner can judge, in the owner\'s language.',
    '   --guide holds the steps the owner follows to create the credential (up to 2000 characters, newlines allowed). It appears on the registration page as guidance from you.',
    '   --valid sets how long the request stays open (default 30 minutes, max 1440). Extend it when the work on the other site will take a while.',
    '   Foundation holds no instructions for anyone else\'s site. Look up what to click now, and write it yourself.',
    '   Why a registration failed, from Foundation\'s side (the code in the events of `foundation request`):',
    '     invalid_values = a field had the wrong shape (empty, newline, too long, wrong format). invalid_credential = the adapter would not accept the value itself.',
    '     reconnect_required = the service rejected the credential (invalid, expired, or the wrong one).',
    '     already_connected = the same credential is registered. confirmation_required / confirmation_locked = wrong confirmation code (5 tries).',
    '3. Wait for the owner. Retry `foundation credentials` every few seconds until the credential appears, then go to 4. Do not hammer it.',
    '   If the owner says it will not work, run `foundation request` and read your own request and what happened on that page (events).',
    '   events is the raw record, in order: page_opened / page_viewed / connect_started / connect_failed (with a code and Foundation\'s own message) / connected / approved / denied / cancelled. What was typed is never recorded.',
    '4. Check: `foundation credentials` gives each credential\'s id, service, and the variables it delivers.',
    '5. Run: foundation exec <id> [<id> ...] -- <command> [args...]',
    '   Several at once is fine (Expo and Apple for one eas build). Do not run when two of them set the same variable name.',
    '   Only the child process gets the variables and FOUNDATION_CREDENTIAL_IDS. Anything delivered as a file (.p8 and such) exists only while the command runs. Never touch a credential outside exec.', '',
    'STORAGE (an approved key may use this at any time, with no request; it stands on its own and needs no adapter)',
    '  One thing is kept: bytes, at a path you choose. Foundation never reads them and has no idea what they are.',
    '  You say how they should reach a command when you write them, and that is the only thing it remembers about them.',
    '   foundation put <path> [--env NAME] [--file NAME] [--secret] [--type <media-type>] [--from <file>]   Bytes on stdin unless --from. Up to 1MB. Writing the same path again replaces it.',
    '     --env NAME     a command receives the bytes as the environment variable NAME (no newlines, up to 16KB)',
    '     --file NAME    the bytes become a file called NAME while the command runs, and --env holds its path (any bytes)',
    '     --secret       you can no longer read them back; they can only be delivered. The owner can still see them.',
    '     no --env       kept but not delivered: notes, state, anything you only read back yourself',
    '   foundation list [<path prefix>]   What is kept: paths, media types, sizes, how each is delivered, and which key wrote it.',
    '   foundation get <path> [--out <file>]   The bytes, as written. Refused for --secret.',
    '   foundation drop <path>',
    '   foundation exec <path> [<path> ...] [<credential-id> ...] -- <command>   Paths and credential ids may be mixed.',
    '  Paths are your only names, and they mean nothing to Foundation: /-separated segments of letters, digits, dot, underscore, hyphen.',
    '  Group by the first segment when you want things grouped; you cannot search inside what is kept, so make the paths tell you what they are.',
    '  Examples of the same one mechanism:',
    '   put github/token --env GH_TOKEN --secret        a key a command reads from the environment',
    '   put apple/key --file AuthKey.p8 --env EXPO_ASC_API_KEY_PATH --secret --from key.p8    bytes a command can only use as a file',
    '   put release/expo-v3 --type application/json     where a procedure got to, for the next conversation to read back',
    '  Foundation does not check any of it. It cannot tell you a value stopped working, so when a command fails on one, replace it.',
    '  Keep what you obtained yourself. A value the owner already holds belongs in a registration, so it never passes through you.',
    '  The owner sees everything kept, can read any of it, and can remove any of it at any time.', '',
    'RULES',
    '- Never print, log or write a credential value. Hand it to a command through exec, and nowhere else.',
    '- Ask for the least you need. Do not request a service the work does not use.',
    '- Be honest in --name and --purpose. The owner decides based on them.',
    '- One pending request at a time. To change it, `foundation cancel` and make a new one. Do not repeat connect.',
    '- If a request is denied or expires, ask the owner why rather than guessing.',
    '- Use a credential you received only for the work it was requested for.', '',
    'Other commands: foundation adapters | credentials | list | shared | request | cancel | whoami | rename <name> | leave (revokes your own key)',
    'Environment: FOUNDATION_URL (required), FOUNDATION_AGENT (optional; this AI\'s name, e.g. claude / codex), FOUNDATION_RUNTIME_KEY_FILE (optional)',
    'One key per machine and OS user by default. FOUNDATION_AGENT gives each AI its own key, but any AI running as the same OS user can read that file, so it is bookkeeping, not protection. To separate them for real, use separate OS users.',
  ].join('\n');
}
