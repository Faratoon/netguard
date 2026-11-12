#!/usr/bin/env bash
# Publish NetGuard to GitHub.
#
#   GITHUB_TOKEN=ghp_xxx ./scripts/push_to_github.sh my-account netguard
#
# Requires a GitHub personal access token with `repo` scope.
set -euo pipefail

ACCOUNT="${1:-}"
REPO="${2:-netguard}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "GITHUB_TOKEN is not set." >&2
  echo "Create one at https://github.com/settings/tokens (scope: repo) and run:" >&2
  echo "  GITHUB_TOKEN=ghp_xxx $0 $ACCOUNT $REPO" >&2
  exit 1
fi
if [[ -z "${ACCOUNT}" ]]; then
  echo "Usage: $0 <github-account> [repo-name]" >&2
  exit 1
fi

cd "${ROOT}"

if [[ ! -d .git ]]; then
  git init -b main
fi

git add -A
git commit -m "feat: NetGuard - router admin, monitoring and parental control dashboard" || true

REMOTE="https://${GITHUB_TOKEN}@github.com/${ACCOUNT}/${REPO}.git"
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "${REMOTE}"
else
  git remote add origin "${REMOTE}"
fi

git push -u origin main
echo "Pushed to https://github.com/${ACCOUNT}/${REPO}"
