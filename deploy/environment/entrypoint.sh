#!/bin/sh
set -eu
umask 077
dockerd --host=unix:///var/run/docker.sock --storage-driver=vfs >/var/log/foundation-docker.log 2>&1 &
daemon_pid=$!
count=0
until docker info >/dev/null 2>&1; do
  if ! kill -0 "$daemon_pid" 2>/dev/null || [ "$count" -ge 60 ]; then
    echo 'The command sandbox could not start.' >&2
    exit 1
  fi
  count=$((count + 1))
  sleep 1
done
exec foundation agent managed
