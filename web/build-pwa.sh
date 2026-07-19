#!/usr/bin/env bash
# Build the WebAssembly engine into the PWA's www/pkg so the page is
# self-contained and installable offline.
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --out-dir www/pkg
echo "PWA ready: serve web/www over HTTP (e.g. 'python -m http.server' in web/www)."
