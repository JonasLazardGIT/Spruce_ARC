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

check_v2_preset_identities() {
	actual_file=$(mktemp "${TMPDIR:-/tmp}/spruce-v2-presets.XXXXXX")
	expected_file=$(mktemp "${TMPDIR:-/tmp}/spruce-v2-presets-expected.XXXXXX")
	go run ./cmd/issuance list-presets |
		awk 'NR > 1 && $1 ~ /^(artifact|pilot|poc|system)-/ { print $1 }' >"$actual_file"
	cat >"$expected_file" <<'EOF'
artifact-n1024-bq10-r96-v2
artifact-n1024-bq16-r96-v2
artifact-n1024-sc125-v2
pilot-n1024-bq32-r96-v2
poc-n1024-bq128-r128-v3
poc-n1024-bq64-r128-v2
poc-n1024-bq96-r128-v2
poc-n512-sc96-v2
system-n1024-wf128-crom-v2
EOF
	if ! cmp -s "$expected_file" "$actual_file"; then
		echo "v2 preset identity boundary mismatch" >&2
		diff -u "$expected_file" "$actual_file" >&2 || true
		rm -f "$actual_file" "$expected_file"
		exit 1
	fi
	rm -f "$actual_file" "$expected_file"
}

run check_gofmt
run go test ./... -count=1
run go vet ./...
if command -v staticcheck >/dev/null 2>&1; then
	run staticcheck ./...
else
	run go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
fi
run_deadcode -test ./...
run_deadcode ./...
run go build ./...

run check_v2_preset_identities
run go run ./cmd/issuance gate-functional-presets \
	-artifact-dir "$artifact_root/smallwood-salted-v2"

if [ "$cleanup_artifacts" -eq 1 ]; then
	echo "artifact validation passed; temporary artifacts removed"
else
	echo "artifact validation passed; artifacts: $artifact_root"
fi
