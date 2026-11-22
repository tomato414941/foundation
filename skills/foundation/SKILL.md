---
name: foundation
description: Use Foundation, a store of credentials and connections, SSH keys among them, that hands them to commands without showing them. Use whenever a task needs an API key, a token, a login or an SSH key, or works with Foundation itself.
---

# foundation

- Foundation keeps credentials as items: variables and connections (logins to
  services and servers, with named outputs). Each item belongs to a
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
- SSH: a connection through the service `ssh` holds a server, an account on it
  and the private key. Keep one per machine and destination, and let every
  session on that machine share it: use the connection that exists instead of
  making another. `foundation ssh-agent CONNECTION -- COMMAND` runs COMMAND
  with SSH_AUTH_SOCK naming a temporary agent that holds the key, and with
  SSH_HOST, SSH_PORT and SSH_USER set.
- The agent drops the key 15 minutes after COMMAND starts. Connections opened
  before then stay open; for a job that connects later, hand over the
  connection's SSH_PRIVATE_KEY output with exec instead, which gives it as a
  file. To give a command both exec's inputs and the agent, put the agent
  inside exec: `foundation exec --inputs ... -- foundation ssh-agent CONNECTION -- COMMAND`.
- A machine makes a connection from values it holds with
  `foundation connect SERVICE --name NAME --field NAME=VALUE ...`, a secret
  given as `@FILE`; for SSH, make the key with ssh-keygen, give it as
  `--field privateKey=@FILE`, and remove the file afterwards.
- Make or store a credential (`foundation keep`, `foundation connect`) only
  when the user asks for it. When Foundation
  answers with a URL for consent or secret input, give the URL to the user.
- When the user has a secret to hand over, such as a new API token, have
  them enter it in Foundation, on the page that `foundation connect SERVICE`
  gives, not write it into a file or the conversation.
