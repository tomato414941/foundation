#!/bin/sh
set -eu
umask 077
session_file="$FOUNDATION_SSH_SESSIONS/$$"
cat "/proc/$$/stat" > "$session_file"
trap 'rm -f "$session_file"' EXIT
cd "$FOUNDATION_SSH_WORKSPACE"
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  /bin/sh -c "$SSH_ORIGINAL_COMMAND"
else
  /bin/bash -l
fi
