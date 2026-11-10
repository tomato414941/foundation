---
name: foundation
description: Use Foundation, a store of credentials, connections and SSH keys that hands them to commands without showing them. Use whenever a task needs an API key, a token, a login or an SSH key, or works with Foundation itself.
---

# foundation

- Foundation keeps credentials as items: variables, connections (logins to
  services, with named outputs) and SSH keys. Each item belongs to a
  principal, such as a machine that has signed in. Commands name items by
  ID. IDs belong to one installation, so keep them out of repositories.
  `foundation --help` lists every command.
- Programs never call Foundation. A program takes its credentials as any
  program would, from environment variables, files or the SSH agent, and the
  command line that runs it is wrapped with Foundation.
- `foundation exec --inputs '[{"name": "VAR", "source": {"id": "ITEM", "output": "OUTPUT"}}]' -- COMMAND`
  runs COMMAND with VAR set to the item's value; `output` picks one of a
  connection's outputs. With `"format": "file"`, VAR names a file that only
  you can read and that holds the value for as long as COMMAND runs.
- exec gives COMMAND only PATH, HOME, LANG, LC_ALL, TZ, TERM and TMPDIR
  besides the inputs, so pass anything else as `-- env NAME=VALUE COMMAND`.
  It runs COMMAND in a process group of its own and passes SIGINT and SIGTERM
  on. `--timeout` does not limit a local command.
- Values that reach exec's output come out as `[redacted]`. Never print a
  value, or any part of one, and never keep one in a file that outlives the
  command that needs it, as `foundation read --output` into `~/.ssh` would.
- SSH keys: keep one per machine and destination, with the private key in
  Foundation, and let every session on that machine share it: use the key
  that exists instead of making another.
  `foundation ssh-key agent KEY -- COMMAND` runs COMMAND with SSH_AUTH_SOCK
  naming a temporary agent that holds the key.
- The agent drops the key 15 minutes after COMMAND starts. Connections opened
  before then stay open; for a job that connects later, hand over the key's
  private-key variable as a file with exec instead. To give a command both
  exec's inputs and the agent, put the agent inside exec:
  `foundation exec --inputs ... -- foundation ssh-key agent KEY -- COMMAND`.
- Make or store a credential (`foundation keep`, `foundation connect`,
  `foundation ssh-key create`) only when the user asks for it. When Foundation
  answers with a URL for consent or secret input, give the URL to the user.
- When the user has a secret to hand over, such as a new API token, have
  them enter it in Foundation, on the page that `foundation connect SERVICE`
  gives, not write it into a file or the conversation.
