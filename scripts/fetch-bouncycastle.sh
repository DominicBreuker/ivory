#!/usr/bin/env bash
# fetch-bouncycastle.sh: download the BouncyCastle jars that the interop
# tests with BouncyCastle's TLS provider need (interop/bc_test.go), from
# Maven Central, and check their SHA-256 sums.
#
# Usage: scripts/fetch-bouncycastle.sh <dir>
# Then: IVORY_BCJARS=<dir> go test ./interop  (with the overlay env)
#
# The version and the sums are pinned below. Files already in <dir> with
# the right sum are not downloaded again.
set -euo pipefail

dir=${1:?usage: fetch-bouncycastle.sh <dir>}
version=1.86
sums="
2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f  bcprov-jdk18on-$version.jar
418e46d6ffd27c3226268533b6321daec899129b1ec8ede35331c7d78e11e535  bctls-jdk18on-$version.jar
1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f  bcutil-jdk18on-$version.jar
8d8b41a4b149bdae8d331f059a578870954d1e3ff29f8269a9eb3ee19a7e4ef7  bcpkix-jdk18on-$version.jar
"

mkdir -p "$dir"
cd "$dir"
for jar in bcprov bctls bcutil bcpkix; do
	file=$jar-jdk18on-$version.jar
	if echo "$sums" | grep " $file\$" | sha256sum -c --status - 2> /dev/null; then
		continue
	fi
	url=https://repo1.maven.org/maven2/org/bouncycastle/$jar-jdk18on/$version/$file
	# Maven Central rate-limits bursts (HTTP 429): retry with a pause.
	for i in 1 2 3 4 5; do
		if curl -sSfL -o "$file.tmp" "$url"; then
			break
		fi
		[ "$i" -lt 5 ] || exit 1
		sleep $((i * 3))
	done
	mv "$file.tmp" "$file"
done
echo "$sums" | grep . | sha256sum -c -
