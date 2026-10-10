#!/usr/bin/env bash
# fetch-tlsfuzzer.sh: set up tlsfuzzer (https://github.com/tlsfuzzer/tlsfuzzer,
# GPL-2.0) for the interop tests F1-F6: a checkout at a pinned commit in
# <dir>/tlsfuzzer and a Python virtual environment in <dir>/venv with
# tlslite-ng and its dependencies from PyPI, pinned by SHA-256.
#
# Usage: scripts/fetch-tlsfuzzer.sh <dir>
# Then: IVORY_TLSFUZZER=<dir> go test -run 'TestF[1-6]' ./interop
#       (with the overlay env)
#
# tlsfuzzer is not on PyPI; its own CI installs the tlslite-ng release
# pinned here. Needs git and python3 with the venv module.
set -euo pipefail

dir=${1:?usage: fetch-tlsfuzzer.sh <dir>}
repo=https://github.com/tlsfuzzer/tlsfuzzer.git
commit=5eebc4464e5197a7f7392fb9acda99cfc32441f7

mkdir -p "$dir"
dir=$(cd "$dir" && pwd)

if [ "$(git -C "$dir/tlsfuzzer" rev-parse HEAD 2> /dev/null)" != "$commit" ]; then
	rm -rf "$dir/tlsfuzzer"
	for i in 1 2 3 4; do
		if git clone -q "$repo" "$dir/tlsfuzzer"; then
			break
		fi
		[ "$i" -lt 4 ] || exit 1
		rm -rf "$dir/tlsfuzzer"
		sleep $((i * 3))
	done
	git -C "$dir/tlsfuzzer" checkout -q "$commit"
fi

python3 -m venv "$dir/venv"
cat > "$dir/requirements.txt" << 'REQ'
tlslite-ng==0.9.0b2 --hash=sha256:d69afaa207972506fcdad4362de09a422f0c8b780f370ec881cf7e789e858aa1
ecdsa==0.19.2 --hash=sha256:840f5dc5e375c68f36c1a7a5b9caad28f95daa65185c9253c0c08dd952bb7399
six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274
REQ
"$dir/venv/bin/pip" install -q --disable-pip-version-check --require-hashes --only-binary=:all: -r "$dir/requirements.txt"
"$dir/venv/bin/python" -c 'import tlslite, ecdsa; print("fetch-tlsfuzzer: tlslite-ng", tlslite.__version__, "ecdsa", ecdsa.__version__)'
echo "fetch-tlsfuzzer: tlsfuzzer $commit in $dir"
