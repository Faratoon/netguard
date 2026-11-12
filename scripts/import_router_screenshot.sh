#!/usr/bin/env bash
# Import a router admin screenshot (or any image) into the NetGuard gallery.
#
#   ./scripts/import_router_screenshot.sh /path/to/router1.jpg [http://localhost:8080]
set -euo pipefail

FILE="${1:-}"
BASE="${2:-http://localhost:8080}"
TOKEN="${NETGUARD_API_TOKEN:-}"

if [[ -z "${FILE}" || ! -f "${FILE}" ]]; then
  echo "Usage: $0 <image-file> [base-url]" >&2
  exit 1
fi

AUTH=()
if [[ -n "${TOKEN}" ]]; then
  AUTH=(-H "X-NetGuard-Token: ${TOKEN}")
fi

curl -sS -X POST "${BASE}/api/media/upload" \
  "${AUTH[@]}" \
  -F "file=@${FILE}" \
  -F "kind=router_admin" \
  -F "title=$(basename "${FILE}")" \
  | tee /dev/stderr | grep -o '"url": *"[^"]*"' || true
