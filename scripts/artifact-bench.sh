#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "use: spruce-artifact bench <preset>" >&2
	exit 2
fi

preset="$1"
case "$preset" in
	*[!A-Za-z0-9._-]*)
		echo "invalid preset selector: $preset" >&2
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
