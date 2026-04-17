#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/web/pkg"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required: https://rustwasm.github.io/wasm-pack/installer/"
  exit 1
fi

rustup target list --installed | grep -q 'wasm32-unknown-unknown' \
  || rustup target add wasm32-unknown-unknown

mkdir -p "${OUT}"
wasm-pack build "${ROOT}/crates/idevice-wasm" \
  --target web \
  --out-dir "${OUT}"

rm -f "${OUT}/.gitignore"
echo "WASM bundle -> ${OUT}"
