#!/usr/bin/env bash
# ivory test PKI. Test only: keys are unprotected. Needs OpenSSL 3.x.
# Usage: scripts/gen-testpki.sh <outdir>
set -euo pipefail
out=${1:?usage: gen-testpki.sh <outdir>}; mkdir -p "$out"; cd "$out"
days=3650   # long validity, so committed fixtures don't expire

eckey()  { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" \
             -pkeyopt ec_param_enc:named_curve -out "$1.key"; }
rsakey() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key"; }

mkca() { # mkca <name> <subject>: self-signed CA
  openssl req -x509 -new -key "$1.key" -subj "$2" -days $days -${md:-sha256} \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.pem"
}
mkee() { # mkee <name> <subject> <ca> <extensions>: end entity signed by <ca>
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
  printf '%b' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial \
    -days $days -${md:-sha256} -extfile "$1.ext" -out "$1.pem"
  rm -f "$1.csr" "$1.ext"
}
SERVER='subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth'
CLIENT='keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth'

# Brainpool PKIs: CA and end entities on the same curve, as in the TI (A_23139).
for c in 256 384 512; do
  case $c in 256) md=sha256;; 384) md=sha384;; 512) md=sha512;; esac
  eckey bp${c}-ca brainpoolP${c}r1;     mkca bp${c}-ca "/CN=ivory Brainpool P${c} Test CA"
  eckey bp${c}-server brainpoolP${c}r1; mkee bp${c}-server "/CN=localhost" bp${c}-ca "$SERVER"
  eckey bp${c}-client brainpoolP${c}r1; mkee bp${c}-client "/CN=ivory Brainpool P${c} Client" bp${c}-ca "$CLIENT"
done
md=sha256
# Negative cases.
eckey bp256-evil-ca brainpoolP256r1    # N2: same subject as bp256-ca, other key
mkca bp256-evil-ca "/CN=ivory Brainpool P256 Test CA"
eckey bp256-wrongkey brainpoolP256r1   # N1: a server signs with this key instead of bp256-server.key
# RSA identities next to the Brainpool ones (the KT holds both: A_17089-03, A_22453).
rsakey rsa-ca;     mkca rsa-ca "/CN=ivory RSA Test CA"
rsakey rsa-server; mkee rsa-server "/CN=localhost" rsa-ca "$SERVER"
rsakey rsa-client; mkee rsa-client "/CN=ivory RSA Client" rsa-ca "$CLIENT"
# Mixed chains: Brainpool leaf under a P-256 CA, and the reverse.
eckey p256-ca P-256; mkca p256-ca "/CN=ivory P-256 Test CA"
eckey bp256-under-p256 brainpoolP256r1; mkee bp256-under-p256 "/CN=localhost" p256-ca "$SERVER"
eckey p256-under-bp256 P-256;           mkee p256-under-bp256 "/CN=localhost" bp256-ca "$SERVER"
# The *.key files are PKCS #8 (genpkey's format). Add SEC 1 copies of the EC
# keys ("EC PRIVATE KEY", named curve), for SEC 1 parsers (A_23511).
for k in *.key; do
  if openssl pkey -in "$k" -noout -text 2>/dev/null | grep -q '^ASN1 OID:'; then
    openssl ec -in "$k" -param_enc named_curve -out "${k%.key}.sec1.pem" 2>/dev/null
  fi
done
rm -f *.srl
