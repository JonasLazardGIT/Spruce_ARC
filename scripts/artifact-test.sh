#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
	echo "use: spruce-artifact test" >&2
	exit 2
fi

go test ./...
