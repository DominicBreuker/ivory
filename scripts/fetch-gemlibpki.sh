#!/usr/bin/env bash
# fetch-gemlibpki.sh: download test data of gematik's reference PKI
# library GemLibPki (github.com/gematik/ref-GemLibPki, Apache License 2.0)
# and check their SHA-256 sums: certificates of the TI test PKI (Brainpool,
# NIST P-256 and RSA) that ti/gemlibpki_test.go checks ivory's ti.Verifier
# against, and test TSLs with their trust anchor GEM.TSL-CA51 (signed with
# brainpoolP256r1) that tsl/gemlibpki_test.go checks package tsl against.
#
# Usage: scripts/fetch-gemlibpki.sh <dir>
# Then: IVORY_GEMLIBPKI=<dir> go test ./ti ./tsl  (with the overlay env)
#
# Certificates land in <dir> without their "certificates/nonqes/" prefix,
# TSLs under <dir>/tsls/.
#
# The commit and the sums are pinned below. Files already in <dir> with
# the right sum are not downloaded again.
set -euo pipefail

dir=${1:?usage: fetch-gemlibpki.sh <dir>}
commit=60c1d974603f7d7cceba29694ecb147b0813031c # v6.0.0
base=https://raw.githubusercontent.com/gematik/ref-GemLibPki/$commit/src/test/resources
sums="
5c7b90dd681374cd8d5dd98b70ad085ac1709e1e7e554c18f44cd443d9b9281b  certificates/nonqes/GEM.SMCB-CA57/GEM.SMCB-CA57-TEST-ONLY.pem
1983aa10caa22684f4089594c6decebca890f028d3b85fecd817d666ca87d30a  certificates/nonqes/GEM.SMCB-CA57/valid/BabetteBeyer-invalid-extension-not-crit.pem
51d0531b4aa8157769b151df7e0fb11a68a8a3e4ab5f933196f6971789b5effb  certificates/nonqes/GEM.SMCB-CA57/valid/BabetteBeyer-missing-admission.pem
724bbc8168a3f7998da9f7dff78bdb94233759692066c17d36d0d7987ae55e8e  certificates/nonqes/GEM.SMCB-CA57/valid/BabetteBeyer-missing-prof-oid.pem
855137f43397a6f452c02354c370c99fab1fc267c704314dc250a2e3bbeb4a0a  certificates/nonqes/GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem
f9bd8d1742c47e58e0e9f4a767194318d760364c23bb69a80dfd7b3ed20f1a9f  certificates/nonqes/GEM.SMCB-CA57/valid/Beyer-Zahnarzt.crt
1a22b7a2ec88a32aa461d33c680b242c851b70a404a0351b934300842cf90b74  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-expired.pem
a68e7c8fc9dd9a1e5730554fe74430c7909fad4b4f873746478f1f75248a2d43  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-authorityKeyId.pem
ae763c8c52d58a0828dc742b6ab2c15533710353b5289e9043e9d000e54570f7  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-certificate-type.pem
3635450cc2664fb864a642ee2c73355b14423acc6165e2d70af3ee403ea2a2ac  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-ext-keyusage.pem
c5d8d3c176ac631ed88b8cd69b200e214b56f352974bfbcb6c3fd76bca16ea4e  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-extension-crit.pem
df67f733dd477f167fdb673e446778bab8d79bbcf6fb5f89077166a9f243a6f1  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-keyusage.pem
d12683e9da5da7d91e5d85920d413af538ecd3b610be483fa0cdbd1808e6802b  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-signature.pem
e029b66220ef11f79d5e602eff9a335ff9e12af8d7f20c24a587c658cf383b19  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-missing-authorityKeyId.pem
db722cf49d2e6344c06c14fa44347f8d1887edbe8519062e8fda32ca1036ea82  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-missing-certificate-type.pem
ba2078704a801df0f6925bd0288673aa55ebddb3f291e9b28117061848614144  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-missing-extKeyUsage.pem
28863179fa85cbad2fb4705f44b75fc656696ca9ca8b096fda9aaf6abee96c24  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-missing-keyUsage.pem
e15129a5529ad3d48b88a936b9b112c21807c96ccd60fcafd1a68f58a47c0cda  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-missing-policyId.pem
511357d87269595ea1dfaff80179d3fe44ca51ab5cb0b7b41d3b876894371c8f  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-not-yet-valid.pem
980fee7649df72026e1e5ba569c6b2d1101085afbcc40c12b1edd6ee58f231c7  certificates/nonqes/GEM.SMCB-CA57/invalid/BabetteBeyer-selfsigned.pem
778cbe6e27a84f0bf9e99a6830925372a151e0bd3c0dd1e05d0742ef6f928e1a  certificates/nonqes/GEM.KOMP-CA57/GEM.KOMP-CA57-TEST-ONLY.pem
c978b04d2de8b3a894a2fd855793987e88f284d113438b9edd16523f9d2f0909  certificates/nonqes/GEM.KOMP-CA57/80276883110000000001-20250721_ecc.crt
44c30e12eda388391da8f3aa1fc7aeca5579139bc42da3bfceacbfe7b6e72a48  certificates/nonqes/GEM.HBA-CA57/BabetteBeyer.pem
e582a4e073a3e076008e4e5eabcf9cff6643aaac7757008f86885ae39cadfc9c  certificates/nonqes/GEM.HBA-CA57/GEM.HBA-CA57-TEST-ONLY.pem
ca6491886f85d55039ff727008e9bfc9a92fa43742038ad45dc57d7286cd8662  certificates/nonqes/GEM.KOMP-CA61/GEM.KOMP-CA61-TEST-ONLY.pem
e3fb2275e9ae47e57e72d1e83c385b777eb64e4d169c5fceabc3db7c34d87edb  certificates/nonqes/GEM.KOMP-CA61/ee_komp_nist_test.pem
1377e9b1bd177d24c074207a824a84978763821a2f65bfe554a02e2573137224  certificates/nonqes/GEM.SMCB-CA41-RSA/GEM.SMCB-CA41.pem
84e62608ef0ce3c6c85a3f72aab0eacce39e52c1739ae0169b5ecfb5afa42595  certificates/nonqes/GEM.SMCB-CA41-RSA/Aschoffsche_Apotheke-AUT-RSA.pem
adc80fbe8b95530dbbec349a839cc67309931bac4bc2d88006ea729e3f7de6a1  certificates/nonqes/GEM.EGK-CA51/GEM.EGK-CA51-TEST-ONLY.pem
73b5532ed23ad6d8cdd6e5c7158e6ae8ac44a96081acbfe439fc4af56c4b68c9  certificates/nonqes/GEM.EGK-CA51/LetitiaBeutelsbacher.pem
299c4de1b7e40946697a6210f27b7a7f651e915495a8c39be295927f39142e86  certificates/nonqes/GEM.TSL-CA51/GEM.TSL-CA51-TEST-ONLY.pem
23b492b7c9e3eb1749bbbaee8f72e10154bf5224e2254537e331d1b1734d66bd  tsls/nonqes/valid/TSL_default.xml
9c7ccd6086762fe572cf3292eeb6604c672d7cc66942419304a0b4e5df30588c  tsls/nonqes/valid/TSL_altCA_revoked.xml
990c8c7dfaec8a5cf0c055016c4a37e12017df4ae654a0984580dfd365229e16  tsls/nonqes/valid/TSL_TAchange.xml
ca64332f0a108031e9c90d63890cb6e08fe4b7ff68125c26b7b83306f471e637  tsls/nonqes/invalid/TSL_invalid_Signature_broken.xml
3c2cb432831a9452b86772d42fc79a314bd40c3dd2f07f1fd48fc438ae952571  tsls/nonqes/invalid/TSL_invalid_xmlNonEtsiTag_altCA.xml
66b74ba19aad3355afc02783eb5095e2c94b1cc68c2fcb7f189d13bcd5780469  tsls/nonqes/invalid/TSL_invalid_xmlNamespace_altCA.xml
7aa394f5b5d7fe72ce8c2e6ddaeaadc1cb23608ccb46a5d2f5b6596b35447a38  tsls/nonqes/defect/TSL_defect_TAchange_twoEntries.xml
d249e6223174c97cc9aded3904660748df6472d8b50bad49e640a4197fcf91cc  tsls/nonqes/defect/TSL_defect_TAchange_broken.xml
"

mkdir -p "$dir"
cd "$dir"
echo "$sums" | grep . | while read -r sum src; do
	file=${src#certificates/nonqes/}
	if echo "$sum  $file" | sha256sum -c --status - 2> /dev/null; then
		continue
	fi
	mkdir -p "$(dirname "$file")"
	for i in 1 2 3 4 5; do
		if curl -sSfL -o "$file.tmp" "$base/$src"; then
			break
		fi
		[ "$i" -lt 5 ] || exit 1
		sleep $((i * 3))
	done
	mv "$file.tmp" "$file"
done
echo "$sums" | grep . | sed 's|  certificates/nonqes/|  |' | sha256sum -c --quiet -
echo "fetch-gemlibpki: $(echo "$sums" | grep -c .) files in $dir"
