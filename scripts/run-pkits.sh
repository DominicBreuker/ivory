#!/usr/bin/env bash
# run-pkits.sh: run gematik's PKI test suite (github.com/gematik/app-PkiTestsuite,
# Apache License 2.0) against examples/fachdienst, the example TI server
# that checks client certificates against the TSL with OCSP.
#
# Usage: scripts/run-pkits.sh <workdir> [test names]
#
# The script clones the suite at a pinned commit into <workdir>/pkits and
# builds it with Maven (Java 17 or later; about 1.5 minutes), writes its
# configuration (product type $PKITS_TYPE, default KimFachdienst; also
# KimFachdienstNist), generates the initial TSL and trust anchor, builds
# and starts the example server with the ivory overlay (profile core), and
# runs the smoke test and then the tests: all tests of allTests.txt, or
# the comma-separated test names given (for example
# "OcspApprovalTests,TslSignerApprovalTests#verifyTslSignerCertExpired").
# All tests take about 80 minutes. The report lands in
# <workdir>/pkits/out/testreport, the server's log in
# <workdir>/fachdienst.log. Ports: $PKITS_PORT (server, default 8443),
# $PKITS_OCSP_PORT (8083), $PKITS_TSL_PORT (8084), all on 127.0.0.1.
set -euo pipefail

work=${1:?usage: run-pkits.sh <workdir> [test names]}
tests=${2:-}
type=${PKITS_TYPE:-KimFachdienst}
port=${PKITS_PORT:-8443}
ocsp_port=${PKITS_OCSP_PORT:-8083}
tsl_port=${PKITS_TSL_PORT:-8084}
commit=3276c94f5b9e75e6bbd77f298d8c9400ca3fba0e # v8.1.0
repo=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$work"
work=$(cd "$work" && pwd)
pkits=$work/pkits
if [ ! -d "$pkits/.git" ]; then
	git clone -q https://github.com/gematik/app-PkiTestsuite "$pkits"
fi
git -C "$pkits" -c advice.detachedHead=false checkout -q "$commit"
if [ ! -f "$pkits/bin/pkits-testsuite-exec.jar" ]; then
	(cd "$pkits" && mvn -q -B package -DskipTests)
fi

mkdir -p "$pkits/config"
cat > "$pkits/config/pkits.yml" << EOF
testObject:
  name: "ivory examples/fachdienst"
  testObjectType: "$type"
  ipAddressOrFqdn: "127.0.0.1"
  port: $port
  ocspGracePeriodSeconds: 3
  ocspToleranceProducedAtPastSeconds: 37
  ocspToleranceProducedAtFutureSeconds: 37
  tslDownloadIntervalSeconds: 3
  tslProcessingTimeSeconds: 3
  ocspTimeoutSeconds: 10

ocspResponder:
  ipAddressOrFqdn: "127.0.0.1"
  port: $ocsp_port

tslProvider:
  ipAddressOrFqdn: "127.0.0.1"
  port: $tsl_port
EOF
rm -rf "$pkits/out"
(cd "$pkits" && ./initialTslAndTa.sh > "$work/initial.log" 2>&1)

# The server identity: the one of the suite's own server simulator, a
# brainpoolP256r1 key under GEM.KOMP-CA58 TEST-ONLY. The suite's client
# doesn't check it.
p12=$pkits/pkits-sut-server-sim/src/main/resources/certificates/tls/pkits-sut-server-sim-KOMP58.p12
openssl pkcs12 -legacy -in "$p12" -passin pass:00 -nokeys -clcerts 2> /dev/null | openssl x509 > "$work/server.pem"
openssl pkcs12 -legacy -in "$p12" -passin pass:00 -nocerts -nodes 2> /dev/null | openssl pkey > "$work/server.key"

"$repo/scripts/ivory-overlay" build -profile core > /dev/null
eval "$("$repo/scripts/ivory-overlay" env -profile core)"
(cd "$repo" && go build -o "$work/fachdienst" ./examples/fachdienst)
"$work/fachdienst" -addr "127.0.0.1:$port" -cert "$work/server.pem" -key "$work/server.key" \
	-tsl "$pkits/out/initialTsl.xml" -trust-anchor "$pkits/out/initialTrustAnchor.pem" \
	-policy 1.2.276.0.76.4.175 -tsl-interval 3s -ocsp-grace 3s -ocsp-timeout 10s \
	> "$work/fachdienst.log" 2>&1 &
server=$!
trap 'kill $server 2> /dev/null || true' EXIT
for _ in $(seq 50); do
	grep -q listening "$work/fachdienst.log" && break
	sleep 0.2
done

cd "$pkits"
./checkInitialState.sh > "$work/check.log" 2>&1 || {
	echo "run-pkits: smoke test failed; see $work/check.log and $work/fachdienst.log" >&2
	exit 1
}
status=0
if [ -n "$tests" ]; then
	java -jar ./bin/pkits-testsuite-exec.jar --tests-names "$tests" > "$work/run.log" 2>&1 || status=$?
else
	./startApprovalTest.sh > "$work/run.log" 2>&1 || status=$?
fi
grep -A6 "Tests Execution Summary" "$work/run.log" | tail -7 || true
grep -h "<--- Test Results" "$work/run.log" | grep -v SUCCESSFUL || true
echo "run-pkits: report in $pkits/out/testreport, logs in $work"
exit "$status"
