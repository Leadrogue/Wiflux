#!/usr/bin/env bash
# Publish Wiflux to GitHub. Requires GH_TOKEN or prior `gh auth login`.
set -euo pipefail

REPO_OWNER="${1:-spryoung2003}"
REPO_NAME="${2:-wiflux}"

if ! command -v gh >/dev/null 2>&1; then
    echo "Error: gh CLI not found. Install from https://cli.github.com/"
    exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
    echo "Not authenticated. Run one of:"
    echo "  export GH_TOKEN=<your-personal-access-token>"
    echo "  gh auth login"
    exit 1
fi

cd "$(dirname "$0")/.."

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git init
    git branch -M main
fi

if ! gh repo view "${REPO_OWNER}/${REPO_NAME}" >/dev/null 2>&1; then
    gh repo create "${REPO_OWNER}/${REPO_NAME}" \
        --public \
        --source=. \
        --remote=origin \
        --description "Modern wireless security auditor with live Rich UI" \
        --push
else
    git remote remove origin 2>/dev/null || true
    git remote add origin "https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
    git push -u origin main
fi

echo "Done: https://github.com/${REPO_OWNER}/${REPO_NAME}"