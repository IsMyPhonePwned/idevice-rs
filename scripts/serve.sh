#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PORT="${1:-8080}"
export IDEVICE_RS_ROOT="${ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required."
  exit 1
fi

if [[ "${BUILD_WASM:-}" == "1" ]]; then
  "${ROOT}/scripts/build-wasm.sh"
fi

if [[ ! -f "${ROOT}/web/pkg/idevice_wasm.js" ]]; then
  echo "WASM bundle missing at web/pkg/ — run scripts/build-wasm.sh or BUILD_WASM=1 $0"
fi

if [[ ! -x "${ROOT}/target/debug/idevice" && ! -x "${ROOT}/target/release/idevice" ]] && [[ -z "${IDEVICE_BIN:-}" ]]; then
  echo "Building idevice CLI (debug)…"
  (cd "${ROOT}" && cargo build -p idevice-cli)
fi

echo "CLI (from repo root): cargo run -p idevice-cli -- list" >&2
cd "${ROOT}/web"
exec python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
import sys
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(os.environ["IDEVICE_RS_ROOT"]).resolve()
WEB_DIR = Path.cwd()

ALLOWED_SUBCOMMANDS = frozenset(
    {
        "list",
        "connect",
        "mux",
        "pair",
        "battery",
        "run",
        "diagnostics",
        "crash-reports",
    }
)


def resolve_idevice_binary() -> Path | None:
    env = os.environ.get("IDEVICE_BIN")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    for name in ("idevice",):
        release = ROOT / "target" / "release" / name
        debug = ROOT / "target" / "debug" / name
        if release.is_file():
            return release
        if debug.is_file():
            return debug
    return None


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, fmt: str, *args_) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args_))

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        if urlparse(self.path).path == "/api/cli":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
        else:
            super().do_OPTIONS()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/cli":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            self._json_error(HTTPStatus.BAD_REQUEST, f"invalid JSON: {e}")
            return

        argv = body.get("argv")
        if not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
            self._json_error(HTTPStatus.BAD_REQUEST, 'expected {"argv": ["idevice", "args", ...]}')
            return

        if not argv:
            self._json_error(HTTPStatus.BAD_REQUEST, "empty argv")
            return

        if argv[0] == "idevice":
            rest = argv[1:]
        else:
            rest = argv

        if not rest:
            self._json_error(HTTPStatus.BAD_REQUEST, "missing subcommand")
            return

        sub = rest[0]
        if sub not in ALLOWED_SUBCOMMANDS:
            self._json_error(HTTPStatus.BAD_REQUEST, f"subcommand not allowed: {sub!r}")
            return

        bin_path = resolve_idevice_binary()
        if bin_path is None:
            self._json_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "idevice binary not found; run `cargo build -p idevice-cli` (or once: `cargo run -p idevice-cli -- --help`) or set IDEVICE_BIN",
            )
            return

        try:
            proc = subprocess.run(
                [str(bin_path), *rest],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            self._json_error(HTTPStatus.GATEWAY_TIMEOUT, "idevice timed out")
            return
        except OSError as e:
            self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        out = {
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        self.wfile.write(json.dumps(out).encode("utf-8"))

    def _json_error(self, status: HTTPStatus, message: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode("utf-8"))


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Serving http://127.0.0.1:{port}/  (static + POST /api/cli)", file=sys.stderr)
    print(f"  Open http://127.0.0.1:{port}/index.html", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
PY
