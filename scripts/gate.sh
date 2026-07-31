#!/usr/bin/env bash
#
# ControlPlane quality gate.
#
# Self-contained: used by CI (.github/workflows/ci.yml) and locally. Runs the
# full Java gate + the contract lint, and exits non-zero on any failure.
#
#   1. ./mvnw verify   — codegen (proto + OpenAPI) + compile + spotless:check
#                        + checkstyle:check + unit tests + Testcontainers IT
#                        (dependency CVE management is handled by Dependabot)
#   2. contracts/lint.sh — buf lint + buf breaking + redocly OpenAPI lint
set -euo pipefail
cd "$(dirname "$0")/.."

# Fast, dependency-free first: the wire-conformance golden must match its committed
# provenance (frames.json's own sha256 + the sha256 of every input proto it was generated
# from). This closes the drift hole (G-b): framegen is a manual dev tool that never runs in
# CI, so without this a stale golden (proto changed, not regenerated) or a hand-edited
# frames.json would propagate to both Rust repos and both conformance suites would pass
# against the WRONG oracle. Pure sha256 — no Rust toolchain needed in the Java pipeline.
# On any mismatch: regenerate the golden + provenance together with
# `(cd contracts/wire/conformance/framegen && cargo run)`.
echo "==> [1/3] wire-conformance golden integrity (frames.json vs provenance)"
prov="contracts/wire/conformance/frames.provenance"
if [ ! -f "$prov" ]; then
	echo "missing $prov — regenerate with (cd contracts/wire/conformance/framegen && cargo run)"
	exit 1
fi
sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
golden_fail=0
while IFS=$'\t' read -r rel want; do
	case "$rel" in '' | \#*) continue ;; esac
	got=$(sha_of "contracts/$rel")
	if [ -z "$got" ]; then
		echo "GOLDEN: cannot read contracts/$rel"
		golden_fail=1
	elif [ "$got" != "$want" ]; then
		echo "GOLDEN DRIFT: contracts/$rel sha256 $got != recorded $want"
		golden_fail=1
	fi
done <"$prov"
[ "$golden_fail" -eq 0 ] || {
	echo "wire-conformance golden drifted — regenerate with (cd contracts/wire/conformance/framegen && cargo run) and commit;"
	echo "frames.json is machine-generated and MUST NOT be hand-edited (a wrong golden is a worse oracle than none)."
	exit 1
}
echo "golden integrity OK"

echo "==> [2/3] ./mvnw -B -ntp verify"
./mvnw -B -ntp verify

echo "==> [3/3] contracts/lint.sh"
./contracts/lint.sh

echo "gate OK"
