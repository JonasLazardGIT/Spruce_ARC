#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "use: spruce-artifact bench <preset>" >&2
	exit 2
fi

preset="$1"
case "$preset" in
n512-compact96|n1024-compact96|n1024-compact125|n1024-q10-128|n1024-q16-128|n1024-q32-128|n1024-q10-96|n1024-q16-96|n1024-q32-96)
	;;
*)
	echo "unknown maintained preset: $preset" >&2
	exit 2
	;;
esac

artifact_root="${ARTIFACT_ROOT:-/artifacts}"
artifact_dir="$artifact_root/$preset"
json_out="$artifact_dir/benchmark-intgenisis-e2e.json"

mkdir -p "$artifact_dir"

exec issuance benchmark-intgenisis-e2e \
	-preset "$preset" \
	-artifact-dir "$artifact_dir" \
	-json-out "$json_out" \
	-force
