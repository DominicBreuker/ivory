#!/usr/bin/env bash
# fetch-tsl-corpus.sh: download a corpus of real TSLs of the TI for the
# regression test tsl.TestTSLCorpus:
#
#   - every version of the production, reference and test TSL archived in
#     https://github.com/spilikin/gematik-tsl-history (since 2025-04),
#     from its git history at a pinned commit;
#   - the two TSLs gematik ships with ZETA Guard
#     (https://github.com/gematik/zeta, zeta-guard-provisioning/), at a
#     pinned commit.
#
# Usage: scripts/fetch-tsl-corpus.sh <dir>
# Then: IVORY_TSL_CORPUS=<dir> go test -run TestTSLCorpus ./tsl
#       (with the overlay env)
#
# The files land in <dir>/prod, <dir>/ref and <dir>/test, named by their
# SHA-256, and in <dir>/invalid the TSLs whose signature must fail;
# tsl/testdata/tsl-corpus.sha256 pins the complete list. To move to newer
# commits, change the pins, run the script with -update (it rewrites the
# list instead of checking it), and review the difference.
set -euo pipefail

update=0
if [ "${1:-}" = -update ]; then
	update=1
	shift
fi
dir=${1:?usage: fetch-tsl-corpus.sh [-update] <dir>}
sums=$(cd "$(dirname "$0")/.." && pwd)/tsl/testdata/tsl-corpus.sha256

history_repo=https://github.com/spilikin/gematik-tsl-history.git
history_commit=59c4b7a0485d1c3156661fb23e79dd461bd9a118
zeta_raw=https://raw.githubusercontent.com/gematik/zeta
zeta_commit=f1d1f2525c699c2de97ae7b9e01a2aa71f0b7cce

# The archived TSLs and their environment. The ".crl" hosts serve the
# same TSLs as the ".tsl" hosts (with a detached signature next to them).
history_paths=(
	"prod downloads/download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml"
	"prod downloads/download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.xml"
	"ref downloads/download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml"
	"ref downloads/download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.xml"
	"test downloads/download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml"
)
# ZETA's test TSL was reformatted (indented) after signing: its digest
# doesn't match, with libxml2 too. The archived original is in test/.
zeta_paths=(
	"prod zeta-guard-provisioning/prod/tsl/ECC_PU_TSL_10322.xml"
	"invalid zeta-guard-provisioning/test/tsl/ECC_TU_TSL_10691.xml"
)

mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
rm -rf "$dir/prod" "$dir/ref" "$dir/test" "$dir/invalid" "$dir/.src"
mkdir -p "$dir/prod" "$dir/ref" "$dir/test" "$dir/invalid"

# store <env> <file>: moves file to <env>/<sha256>.xml.
store() {
	local s
	s=$(sha256sum "$2" | cut -d' ' -f1)
	mv "$2" "$dir/$1/$s.xml"
}

src=$dir/.src
for i in 1 2 3 4; do
	if git clone -q "$history_repo" "$src"; then
		break
	fi
	[ "$i" -lt 4 ] || exit 1
	rm -rf "$src"
	sleep $((i * 3))
done
git -C "$src" checkout -q "$history_commit"
for entry in "${history_paths[@]}"; do
	env=${entry%% *}
	path=${entry#* }
	for c in $(git -C "$src" log --format=%H "$history_commit" -- "$path"); do
		# A commit that deleted the file has no version of it.
		if git -C "$src" show "$c:$path" > "$dir/tmp.xml" 2> /dev/null; then
			store "$env" "$dir/tmp.xml"
		fi
	done
done
rm -rf "$src" "$dir/tmp.xml"

for entry in "${zeta_paths[@]}"; do
	env=${entry%% *}
	path=${entry#* }
	for i in 1 2 3 4; do
		if curl -sSfL -o "$dir/tmp.xml" "$zeta_raw/$zeta_commit/$path"; then
			break
		fi
		[ "$i" -lt 4 ] || exit 1
		sleep $((i * 3))
	done
	store "$env" "$dir/tmp.xml"
done

cd "$dir"
if [ "$update" = 1 ]; then
	find prod ref test invalid -name '*.xml' | LC_ALL=C sort | xargs sha256sum > "$sums"
	echo "fetch-tsl-corpus: $(wc -l < "$sums") TSLs; list written to $sums"
	exit 0
fi
want=$(wc -l < "$sums")
got=$(find prod ref test invalid -name '*.xml' | wc -l)
if [ "$want" != "$got" ]; then
	echo "fetch-tsl-corpus: $got TSLs, want $want (tsl/testdata/tsl-corpus.sha256)" >&2
	exit 1
fi
sha256sum -c --quiet "$sums"
echo "fetch-tsl-corpus: $got TSLs in $dir"
