#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
	echo "use: spruce-artifact gate" >&2
	exit 2
fi

artifact_root="${ARTIFACT_ROOT:-/artifacts}"
gate_root="$artifact_root/degree1024-gate"

mkdir -p "$gate_root"

exec issuance gate-degree1024-maintained-presets -artifact-root "$gate_root"
