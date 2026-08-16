#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

REDOCLY_VERSION="${REDOCLY_VERSION:-1.34.5}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

echo "==> [1/3] buf lint"
( cd proto && buf lint )
grn "    buf lint: OK"

echo "==> [2/3] buf breaking (against main baseline)"
repo_root="$(git -C "$here" rev-parse --show-toplevel)"
base_ref=""
for r in origin/main main; do
  if git -C "$here" rev-parse --verify --quiet "${r}^{commit}" >/dev/null 2>&1; then
    base_ref="$r"
    break
  fi
done
if [ -z "$base_ref" ]; then
  if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
    red "    buf breaking: FAILED — no 'main' ref available in CI (checkout likely missing fetch-depth: 0)"
    exit 1
  fi
  grn "    buf breaking: no 'main' ref available locally (shallow checkout) — skipped"
elif ! git -C "$here" cat-file -e "${base_ref}:contracts/proto/buf.yaml" 2>/dev/null; then
  grn "    buf breaking: 'main' has no contracts/proto baseline yet (first introduction) — skipped"
else
  base_sha="$(git -C "$here" rev-parse "${base_ref}")"
  ( cd proto && buf breaking --against "${repo_root}/.git#ref=${base_sha},subdir=contracts/proto" )
  grn "    buf breaking: OK (baseline ${base_ref} @ ${base_sha:0:12})"
fi

echo "==> [3/3] redocly lint (OpenAPI 3.1)"
npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint openapi/openapi.yaml
grn "    redocly lint: OK"

grn "==> contracts: all checks passed"
