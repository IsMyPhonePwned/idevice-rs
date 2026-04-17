#!/usr/bin/env bash
# Rebuild WASM then serve **web/** with Python’s static HTTP server (WASM + index.html stay in sync).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8080}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

if [[ "${SKIP_WASM_BUILD:-}" == "1" ]]; then
  echo "SKIP_WASM_BUILD=1 — skipping ./scripts/build-wasm.sh" >&2
else
  "${ROOT}/scripts/build-wasm.sh"
fi

cd "${ROOT}/web"
echo "Serving http://127.0.0.1:${PORT}/  (static files; open /index.html)" >&2
exec python3 -m http.server "${PORT}" --bind 127.0.0.1
