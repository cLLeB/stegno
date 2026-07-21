#!/usr/bin/env bash
# Serve the built PWA locally.
#
# Bound to 127.0.0.1 so the app is never exposed on the network — it is an
# offline tool and nothing should reach it from another machine. The port sits
# in the IANA dynamic range rather than on 8080/8000, which collide with nearly
# every other dev server. Override with STEGNO_PORT.
set -euo pipefail
cd "$(dirname "$0")/www"

PORT="${STEGNO_PORT:-47823}"

if [ ! -f pkg/stegno_web_bg.wasm ]; then
  echo "engine not built yet — run ./build-pwa.sh first" >&2
  exit 1
fi

echo "Stegno PWA: http://127.0.0.1:${PORT}"
python -m http.server "$PORT" --bind 127.0.0.1
