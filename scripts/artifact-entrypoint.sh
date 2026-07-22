#!/bin/sh
set -eu

show_help() {
	cat <<'EOF'
use: spruce-artifact <command> [args]

commands:
	  help                  show this help
	  test                  run go test ./...
	  list                  list every executable PoC preset
	  bench <preset>        run an E2E preset benchmark
	  gate                  functionally validate every executable preset
	  artifact-gate         reproduce historical exact-byte results
	  validate              run tests, vet, staticcheck, deadcode, and all E2E checks
EOF
}

command="${1:-help}"

case "$command" in
help|-h|--help)
	show_help
	;;
test)
	shift
	exec ./scripts/artifact-test.sh "$@"
	;;
list)
	shift
	exec issuance list-presets "$@"
	;;
bench)
	shift
	exec ./scripts/artifact-bench.sh "$@"
	;;
gate)
	shift
	gate_root="${ARTIFACT_ROOT:-/artifacts}/functional-gate"
	exec issuance gate-functional-presets -artifact-dir "$gate_root" "$@"
	;;
artifact-gate)
	shift
	exec ./scripts/artifact-gate.sh "$@"
	;;
validate)
	shift
	export ARTIFACT_ROOT="${ARTIFACT_ROOT:-/artifacts/validate}"
	exec ./scripts/validate-artifact.sh "$@"
	;;
*)
	echo "unknown command: $command" >&2
	show_help >&2
	exit 2
	;;
esac
