#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Parley: keep a bot away from the daemon's local socket (Linux), with bubblewrap (https://github.com/containers/bubblewrap).
#
#   linux-bwrap.sh <parley state directory> <bot command> [args...]
#
# The state directory is the one that holds parleyd.sock (the config directory unless the daemon was given another).
# It is replaced by an empty in-memory directory inside the sandbox, so the socket's path leads nowhere; the daemon's
# processes are invisible (new PID namespace); the bot has no controlling terminal (--new-session). The rest of the file
# system is read-only (add --bind <dir> <dir> for the folder the bot must write to) and the network is shared. Parley's socket is a file-system socket, never an abstract one.
set -eu
[ $# -ge 2 ] || { echo "usage: $0 <parley state directory> <bot command> [args...]" >&2; exit 2; }
state=$1
shift
exec bwrap \
  --ro-bind / / --dev /dev --proc /proc \
  --tmpfs "$state" \
  --unshare-user --unshare-pid --unshare-ipc --unshare-uts \
  --die-with-parent --new-session \
  -- "$@"
