#!/usr/bin/env bash
# build-openssl.sh: build an OpenSSL release from source into a prefix, for
# the TLS 1.3 interop tests (OpenSSL >= 3.2 has the Brainpool groups and
# signature schemes of RFC 8734 in TLS 1.3).
#
# Usage: scripts/build-openssl.sh <version> <sha256 of the tarball> <prefix>
#
# The tarball comes from the GitHub release of openssl/openssl and must
# match the checksum. The build is static (no-shared), so <prefix>/bin/openssl
# runs without LD_LIBRARY_PATH. Nothing happens if <prefix>/bin/openssl
# already reports <version>.
set -euo pipefail

version=${1:?usage: build-openssl.sh <version> <sha256> <prefix>}
sum=${2:?usage: build-openssl.sh <version> <sha256> <prefix>}
prefix=${3:?usage: build-openssl.sh <version> <sha256> <prefix>}

if [ -x "$prefix/bin/openssl" ] && "$prefix/bin/openssl" version | grep -q "^OpenSSL $version "; then
	"$prefix/bin/openssl" version
	exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tarball=$work/openssl-$version.tar.gz
curl -sSfL -o "$tarball" "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz"
echo "$sum  $tarball" | sha256sum -c -
tar -xzf "$tarball" -C "$work"
(
	cd "$work/openssl-$version"
	./Configure no-shared no-docs no-tests --prefix="$prefix" --libdir=lib linux-x86_64 >/dev/null
	make -j"$(nproc)" >/dev/null
	make install_sw >/dev/null
)
"$prefix/bin/openssl" version
