#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_root"

if [ "${ARTIFACT_ROOT:-}" = "" ]; then
	artifact_root=$(mktemp -d "${TMPDIR:-/tmp}/spruce-artifact-validate.XXXXXX")
	cleanup_artifacts=1
else
	artifact_root=$ARTIFACT_ROOT
	cleanup_artifacts=0
	mkdir -p "$artifact_root"
fi

cleanup() {
	if [ "$cleanup_artifacts" -eq 1 ]; then
		rm -rf "$artifact_root"
	fi
}
trap cleanup EXIT INT TERM

run() {
	printf '\n==> %s\n' "$*"
	"$@"
}

run_deadcode() {
	printf '\n==> deadcode %s\n' "$*"
	out=$(mktemp "${TMPDIR:-/tmp}/spruce-deadcode.XXXXXX")
	if command -v deadcode >/dev/null 2>&1; then
		deadcode_bin=deadcode
	else
		run go install golang.org/x/tools/cmd/deadcode@v0.36.0
		deadcode_bin="$(go env GOPATH)/bin/deadcode"
	fi
	if ! "$deadcode_bin" "$@" >"$out" 2>&1; then
		cat "$out" >&2
		rm -f "$out"
		exit 1
	fi
	if [ -s "$out" ]; then
		cat "$out" >&2
		rm -f "$out"
		exit 1
	fi
	rm -f "$out"
}

check_gofmt() {
	out=$(mktemp "${TMPDIR:-/tmp}/spruce-gofmt.XXXXXX")
	find . -name '*.go' -not -path './external/*' -not -path './.git/*' -print | xargs gofmt -l >"$out"
	if [ -s "$out" ]; then
		cat "$out" >&2
		rm -f "$out"
		exit 1
	fi
	rm -f "$out"
}

showing_bytes_from_report() {
	awk '
		/"showing": \{/ { in_showing = 1; next }
		in_showing && /"paper_transcript_bytes":/ {
			line = $0
			gsub(/[^0-9]/, "", line)
			got = line
		}
		END { if (got != "") print got }
	' "$1"
}

check_preset() {
	preset=$1
	expected=$2
	artifact_dir="$artifact_root/$preset"
	report="$artifact_dir/benchmark-intgenisis-e2e.json"
	mkdir -p "$artifact_dir"

	run go run ./cmd/issuance benchmark-intgenisis-e2e \
		-preset "$preset" \
		-artifact-dir "$artifact_dir" \
		-json-out "$report" \
		-force

	got=$(showing_bytes_from_report "$report")
	if [ "$got" != "$expected" ]; then
		echo "$preset showing.paper_transcript_bytes=$got, want $expected" >&2
		exit 1
	fi
	echo "$preset showing.paper_transcript_bytes=$got"
}

run check_gofmt
run go test ./...
run go vet ./...
if command -v staticcheck >/dev/null 2>&1; then
	run staticcheck ./...
else
	run go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
fi
run_deadcode -test ./...
run_deadcode ./...
run go build ./cmd/issuance ./cmd/showing

check_preset n512-compact96 22016
check_preset n1024-compact96 26144
check_preset n1024-compact125 35223
check_preset n1024-q10-128 37093
check_preset n1024-q16-128 42070
check_preset n1024-q32-128 48691
check_preset n1024-q10-96 29653
check_preset n1024-q16-96 30591
check_preset n1024-q32-96 37257

if [ "$cleanup_artifacts" -eq 1 ]; then
	echo "artifact validation passed; temporary artifacts removed"
else
	echo "artifact validation passed; artifacts: $artifact_root"
fi
