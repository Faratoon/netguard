#!/usr/bin/env bash
# Start a public Cloudflare tunnel to the local NetGuard instance and print the URL.
#
#   ./scripts/tunnel.sh          # start tunnel, print URL
#   ./scripts/tunnel.sh stop     # stop the tunnel
set -euo pipefail

BIN="${HOME}/.local/bin/cloudflared"
URL="http://127.0.0.1:8080"

if [[ "${1:-}" == "stop" ]]; then
  pkill -f "cloudflared tunnel" || true
  echo "tunnel stopped"
  exit 0
fi

if [[ ! -x "${BIN}" ]]; then
  mkdir -p "$(dirname "${BIN}")"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64) asset=cloudflared-linux-amd64 ;;
    aarch64|arm64) asset=cloudflared-linux-arm64 ;;
    *) echo "unsupported arch: ${arch}" >&2; exit 1 ;;
  esac
  curl -sSL -o "${BIN}" "https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}"
  chmod +x "${BIN}"
fi

pkill -f "cloudflared tunnel" 2>/dev/null || true
setsid nohup "${BIN}" tunnel --url "${URL}" --no-autoupdate > /tmp/cloudflared.log 2>&1 &

for _ in $(seq 1 30); do
  link="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cloudflared.log | head -1 || true)"
  if [[ -n "${link}" ]]; then
    echo "NetGuard public URL: ${link}"
    exit 0
  fi
  sleep 1
done

echo "tunnel did not start, see /tmp/cloudflared.log" >&2
exit 1
