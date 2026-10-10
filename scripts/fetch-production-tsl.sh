#!/usr/bin/env bash
# fetch-production-tsl.sh: download the current TSL of one of the TI's
# environments and its trust anchor, the TSL signer CA certificate, which
# the TSL service publishes next to it (gemSpec_TSL TIP1-A_4074):
#
#   prod  TSL(ECC-RSA) of the production environment,
#         https://download.tsl.ti-dienste.de/ECC/, anchor GEM.TSL-CA3
#   ref   the reference environment's TSL,
#         https://download-ref.tsl.ti-dienste.de/ECC/, and
#   test  the test environment's TSL,
#         https://download-test.tsl.ti-dienste.de/ECC/, both with the
#         anchor GEM.TSL-CA28 TEST-ONLY (published on the test host only)
#
# Usage: scripts/fetch-production-tsl.sh <dir> [prod|ref|test]  (default prod)
# Then: IVORY_PRODUCTION_TSL=<dir> go test -run TestProductionTSL ./tsl
#       (with the overlay env)
#
# The TSL is checked against the hash file the service publishes with it,
# the trust anchor against the SHA-256 fingerprint pinned below. A product
# must confirm the anchor's fingerprint through an independent channel
# before it trusts it (gemSpec_PKI GS-A_4640; the TSL service sends it by
# letter on request, TIP1-A_4075). When gematik announces a new anchor,
# the TSL lists it as TSLServiceCertChange; update the pin then.
set -euo pipefail

dir=${1:?usage: fetch-production-tsl.sh <dir> [prod|ref|test]}
env=${2:-prod}
case $env in
prod)
	base=https://download.tsl.ti-dienste.de/ECC
	tsl=ECC-RSA_TSL
	anchor_url=$base/GEM.TSL-CA3.der
	anchor=GEM.TSL-CA3.der
	anchor_sha256=e2992dc292f6aa8d9e462a7723f54c162853b4056c277260b82ce58921408448
	;;
ref | test)
	base=https://download-$env.tsl.ti-dienste.de/ECC
	tsl=ECC-RSA_TSL-$env
	anchor_url=https://download-test.tsl.ti-dienste.de/ECC/C.GEM.TSL-CA28_TEST-ONLY.der
	anchor=GEM.TSL-CA28_TEST-ONLY.der
	anchor_sha256=43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a
	;;
*)
	echo "fetch-production-tsl: unknown environment $env (prod, ref or test)" >&2
	exit 2
	;;
esac

mkdir -p "$dir"
cd "$dir"
get() {
	for i in 1 2 3 4; do
		if curl -sSfL --compressed -o "$2.tmp" "$1"; then
			mv "$2.tmp" "$2"
			return
		fi
		[ "$i" -lt 4 ] || return 1
		sleep $((i * 3))
	done
}
get "$base/$tsl.xml" "$tsl.xml"
get "$base/$tsl.sha2" "$tsl.sha2"
get "$anchor_url" "$anchor"
want=$(tr -d '[:space:]' < "$tsl.sha2" | tr 'A-F' 'a-f' | cut -c1-64)
got=$(sha256sum "$tsl.xml" | cut -d' ' -f1)
if [ "$want" != "$got" ]; then
	echo "fetch-production-tsl: TSL hash $got doesn't match the published hash $want" >&2
	exit 1
fi
echo "$anchor_sha256  $anchor" | sha256sum -c --quiet -
echo "fetch-production-tsl: $env TSL ($(wc -c < "$tsl.xml") bytes) and $anchor in $dir"
