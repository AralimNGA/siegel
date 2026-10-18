#!/bin/bash
# Grep-Sperren der Windows-Version (SPEC-WINDOWS W3): ruft sperren_windows.py auf (läuft auch unter Windows direkt).
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/sperren_windows.py" "$@"
