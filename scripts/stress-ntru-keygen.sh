#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"

preset="${1:-n1024-compact125}"
runs="${NTRU_STRESS_RUNS:-20}"

case "$preset" in
n512-compact96|n1024-compact96|n1024-compact125|n1024-q10-128|n1024-q16-128|n1024-q32-128|n1024-q10-96|n1024-q16-96|n1024-q32-96)
	;;
*)
	echo "unknown maintained preset: $preset" >&2
	exit 2
	;;
esac

i=1
while [ "$i" -le "$runs" ]; do
	dir=$(mktemp -d "${TMPDIR:-/tmp}/spruce-ntru-keygen.XXXXXX")
	trap 'rm -rf "$dir"' EXIT INT TERM
	echo "NTRU keygen stress $i/$runs preset=$preset"
	go run ./cmd/issuance setup-ntru-keys \
		-preset "$preset" \
		-params-out "$dir/ntru_params.json" \
		-public-out "$dir/ntru_public.json" \
		-private-out "$dir/ntru_private.json" \
		-force
	rm -rf "$dir"
	trap - EXIT INT TERM
	i=$((i + 1))
done

echo "NTRU keygen stress passed: preset=$preset runs=$runs"
