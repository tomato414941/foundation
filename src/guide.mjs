// Printed by `foundation --help`. Written for an AI agent that has just been told to use something of its
// owner's and needs the whole thing in one read. What each acquisition is comes from the server's own list;
// nothing about any service is written here.
// This text is read by the agent, not by the owner, so it is English; everything the owner reads
// (purposes, guidance, the dashboard) stays in the owner's language.
function adapterLines(adapters) {
  if (!adapters) return ['   Run `foundation adapters` for what this server can obtain itself (needs FOUNDATION_URL).'];
  const lines = [];
  for (const adapter of adapters.filter(item => item.available)) {
    lines.push('   ' + adapter.id + '  ' + (adapter.service?.name || '') + ' / ' + adapter.access.name + (adapter.variables.length ? '  delivers: ' + adapter.variables.join(', ') : ''));
    lines.push('     foundation connect --adapter ' + adapter.id + ' --purpose "<purpose>"');
    if (adapter.ai) lines.push('     ' + adapter.ai);
  }
  const unavailable = adapters.filter(item => !item.available);
  if (unavailable.length) lines.push('   Currently unavailable: ' + unavailable.map(item => item.id).join(', '));
  return lines;
}

export function guide(adapters) {
  return ['Foundation is a store. It keeps what belongs to its owner, and hands it to the commands you run.',
    'One thing is kept: bytes, at a path. Foundation never reads them and has no idea what they are, so anything can go in.',
    'A short string delivered as a variable is what others call a key and a value; a JSON body you read back is a document;',
    'a PEM delivered as a file is a file. Here they are one mechanism, and a kind of content nobody has thought of needs no change.',
    'Never ask the owner to paste a key or token into the chat. It goes into the store.', '',
    'Your standing: you hold one access key. Once the owner approves it, you may use everything they keep.',
    '  `foundation whoami` tells you your key\'s name (401 not_approved if it is not approved yet).', '',
    'APPROVAL (first time only)',
    '   If `foundation whoami` returns 401 not_approved, run `foundation connect` (no options; --name to change the name)',
    '   and give the owner the verification_uri and the confirmation_code from the output. Always show the code: they type it.',
    '   Retry `foundation whoami` every few seconds until it passes. Do not hammer it.', '',
    'USING THE STORE',
    '   foundation put <path> [--env NAME] [--file NAME] [--secret] [--type <media-type>] [--from <file>] [--if-version <n>]',
    '     Bytes on stdin unless --from. Up to 1MB. Writing the same path again replaces it.',
    '     --env NAME     a command receives the bytes as the environment variable NAME (no newlines, up to 16KB)',
    '     --file NAME    the bytes become a file called NAME while the command runs, and --env holds its path (any bytes)',
    '     --secret       you can no longer read them back; they can only be delivered. The owner can still see them.',
    '     no --env       kept but not delivered: notes, state, anything you only read back yourself',
    '     --if-version   refuse to write unless this is still the version you last saw (409 version_conflict). Use it',
    '                    whenever you are updating something you read, so two conversations at once cannot lose each other\'s work.',
    '   foundation list [<path prefix>]   What is kept: paths, media types, sizes, how each is delivered, its version, and who wrote it.',
    '   foundation get <path> [--out <file>]   The bytes, as written. Refused for --secret.',
    '   foundation drop <path>',
    '   foundation exec <path> [<path> ...] -- <command> [args...]   Runs the command with those in place, and nothing else.',
    '     Only the child process gets them. A file exists only while the command runs. FOUNDATION_PATHS lists what was used.',
    '     Never read or copy what is delivered outside the command that needs it.',
    '   Paths are your only names, and they mean nothing to Foundation: /-separated segments of letters, digits, dot, underscore, hyphen.',
    '   Group by the first segment when you want things grouped; you cannot search inside what is kept, so make the paths tell you what they are.',
    '     put github/token --env GH_TOKEN --secret                         a key a command reads from the environment',
    '     put apple/key --file AuthKey.p8 --env EXPO_ASC_API_KEY_PATH --secret --from key.p8    bytes usable only as a file',
    '     put release/expo-v3 --type application/json                      where a procedure got to, for the next conversation',
    '   Foundation checks none of it. It cannot tell you something stopped working, so when a command fails on one, replace it.',
    '   The owner sees everything kept, can read any of it, and can remove any of it at any time.', '',
    'FILLING THE STORE: two ways, and neither is required of you.',
    '',
    '1. Put it there yourself. Anything you obtained or wrote: `foundation put`, above.',
    '',
    '2. Ask the owner, for what only they can fetch -- an API token, a key, a certificate they must go and create.',
    '   foundation ask <path> --label "<what they should paste>" [--env NAME] [--file NAME] [--site <https://where it is made>] [--multiline] [--readable] [--purpose "..."] [--guide "..."] [--valid <minutes>]',
    '   Give the owner the verification_uri from the output (there is no code). What you declare is the whole request:',
    '     <path>      where it will be kept, beside everything else',
    '     --label     what they are being asked for, in their language. It titles the screen and names the field.',
    '     --env/--file  how it will reach a command, exactly as in put. Leave both out for something only read back.',
    '     --site      the page where they make it, offered as a link',
    '     --guide     the steps they follow (up to 2000 characters). Foundation holds no instructions for anyone else\'s site:',
    '                 look up what to click now, and write it yourself.',
    '     --readable  you may read it back afterwards. Without it, you can only have it delivered.',
    '     --valid     how long the link stays open (default 30 minutes, max 1440)',
    '   When they finish, it is simply kept: `foundation list` shows it and `foundation exec <path>` hands it over.',
    '   Ask for what the owner already holds. Never take it through the conversation and put it there yourself.',
    '',
    '3. Have Foundation obtain it, for the few services where nobody else can: an OAuth exchange that needs the',
    '   operator\'s own client secret, or a login relayed once. Foundation then keeps it current and can revoke it.',
    ...adapterLines(adapters),
    '   foundation connect --adapter <adapter> --purpose "<purpose>" [--guide "<instructions>"] [--valid <minutes>]',
    '   Give the owner the verification_uri (there is no code). Write the purpose as one concrete sentence they can judge, in their language.',
    '   `foundation connections` shows what is connected and the paths each one keeps; use those paths with exec like any other.',
    '   Wait by retrying `foundation list` every few seconds. Do not hammer it.',
    '   If the owner says it will not work, run `foundation request` and read your own request and what happened at its page (events).',
    '   events is the raw record, in order: page_opened / page_viewed / connect_started / connect_failed (with a code and',
    '   Foundation\'s own message) / connected / stored / approved / denied / cancelled. What was typed is never recorded.', '',
    'TOOL: sharing space (use it or not; nothing depends on it). The store is private; this is the opposite.',
    '   foundation share <file> [--type <content-type>] [--minutes <n>]   Publishes a file and returns a time-limited read URL. Up to 5MB, gone after 7 days.',
    '   Anyone with the URL can read that one file (no writing, no listing). A file you shared cannot be changed. Share another one instead.',
    '   The URL is an S3 presigned URL, so it works anywhere an S3 URL is required (CloudFormation quickcreate?templateURL=, for one).',
    '   `foundation shared` lists them, `foundation link <file-id> [--minutes <n>]` issues the URL again (default 60 minutes, max 10080). Never share a secret.', '',
    'RULES',
    '- Never print, log or write out what is delivered. Hand it to a command through exec, and nowhere else.',
    '- Ask for the least you need. Do not request something the work does not use.',
    '- Be honest in --name, --purpose and --label. The owner decides based on them.',
    '- One pending request at a time. To change it, `foundation cancel` and make a new one. Do not repeat connect or ask.',
    '- If a request is denied or expires, ask the owner why rather than guessing.',
    '- Use what you receive only for the work it was asked for.', '',
    'Other commands: foundation adapters | connections | list | shared | request | cancel | whoami | rename <name> | leave (revokes your own key)',
    'Environment: FOUNDATION_URL (required), FOUNDATION_AGENT (optional; this AI\'s name, e.g. claude / codex), FOUNDATION_RUNTIME_KEY_FILE (optional)',
    'One key per machine and OS user by default. FOUNDATION_AGENT gives each AI its own key, but any AI running as the same OS user can read that file, so it is bookkeeping, not protection. To separate them for real, use separate OS users.',
  ].join('\n');
}
