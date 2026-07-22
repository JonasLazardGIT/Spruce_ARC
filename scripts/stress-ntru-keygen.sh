#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"

preset="${1:-n1024-compact125}"
runs="${NTRU_STRESS_RUNS:-20}"

case "$preset" in
*[!A-Za-z0-9._-]*)
	echo "invalid preset selector: $preset" >&2
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
