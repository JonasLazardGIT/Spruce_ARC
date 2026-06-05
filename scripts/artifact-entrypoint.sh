#!/bin/sh
set -eu

show_help() {
	cat <<'EOF'
use: spruce-artifact <command> [args]

commands:
  help                  show this help
  test                  run go test ./...
  bench <preset>        run maintained IntGenISIS E2E benchmark
  gate                  run maintained exact-byte gate
  validate              run tests, vet, staticcheck, deadcode, and all E2E checks

maintained presets:
  n512-compact96
  n1024-compact96
  n1024-compact125
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
bench)
	shift
	exec ./scripts/artifact-bench.sh "$@"
	;;
gate)
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
