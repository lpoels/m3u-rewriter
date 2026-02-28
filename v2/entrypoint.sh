#!/usr/bin/env bash
set -e

# If running as root, fix ownership of /output then drop privileges
if [ "$(id -u)" = "0" ]; then
  chown -R app:app /output || true
  exec gosu app "$@"
fi

# Already non-root
exec "$@"
