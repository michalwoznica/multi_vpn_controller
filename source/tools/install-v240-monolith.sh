#!/usr/bin/env bash
# Compatibility entrypoint retained for the 2.4.x source-tree filename.
# The active release installer is install-v241-monolith.sh.
set -euo pipefail
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
exec "$HERE/install-v241-monolith.sh" "$@"
