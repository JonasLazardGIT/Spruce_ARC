#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
	echo "use: spruce-artifact gate" >&2
	exit 2
fi

artifact_root="${ARTIFACT_ROOT:-/artifacts}"
gate_root="$artifact_root/maintained-gate"

mkdir -p "$gate_root"

exec issuance gate-maintained-presets -artifact-root "$gate_root"
