#!/usr/bin/env bash
# Build the WebAssembly engine into the PWA's www/pkg so the page is
# self-contained and installable offline.
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --out-dir www/pkg

# 8080 and 8000 collide with almost everything; this port is in the IANA
# dynamic range and is not claimed by any common dev server.
PORT="${STEGNO_PORT:-47823}"
echo "PWA ready. Serve it with:"
echo "    ./serve-pwa.sh          # http://127.0.0.1:${PORT}"
