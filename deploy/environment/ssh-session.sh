#!/bin/sh
set -eu
umask 077
session_file="$FOUNDATION_SSH_SESSIONS/$$"
temporary_file="$FOUNDATION_SSH_SESSIONS/.$$"
trap 'rm -f "$session_file" "$temporary_file"' EXIT
cat "/proc/$$/stat" > "$temporary_file"
mv "$temporary_file" "$session_file"
cd "$FOUNDATION_SSH_WORKSPACE"
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  /bin/sh -c "$SSH_ORIGINAL_COMMAND"
else
  /bin/bash -l
fi
