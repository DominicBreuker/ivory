# Changelog

ivory follows [semantic versioning](https://semver.org/). Before v1.0.0,
a minor version may change APIs. Each version supports one Go release
(README.md, "Supported Go versions"); a new Go patch release gives a new
ivory patch version.

## v0.2.0

**New packages:**

- `ocsp`: OCSP requests and responses whose responders sign with
  Brainpool, NIST or RSA keys. `golang.org/x/crypto/ocsp` rejects every
  response that embeds a Brainpool signer certificate; this package
  parses responses itself. `Response.Verify` implements the response
  checks of gemSpec_PKI TUC_PKI_006 (signer from the TSL, signature,
  CertID, the 37.5 s tolerances of GS-A_5215, certHash, status), with
  errors named after gemSpec_PKI's error codes. `Checker` sends requests
  over HTTP and reuses good responses for a grace period.
  `CreateResponse` builds responses with any `crypto.Signer`, for test
  responders.
- `tsl`: the TI's trust-service status list. `Parse` checks the XML
  against the schema of ETSI TS 102 231 (TUC_PKI_020); `TSL.Verify`
  checks the signer certificate against the trust anchor (TUC_PKI_011)
  and the XML signature, made with brainpoolP256r1 or RSA (TUC_PKI_012).
  `Updater` keeps the trust space current (TUC_PKI_001 with TUC_PKI_013,
  -016, -017 and -019), and `TSL.Status` checks a certificate's CA status
  in the TSL, the certificate type (TUC_PKI_007) and its OCSP status for
  `ti.Verifier`.

**Added:**

- `ti.Verifier.Status`: a function called last with the certificate and
  its CA, for checks such as `tsl.TSL.Status`.
- `tlsutil.TLS12Fallback` (opt-in): a `GetConfigForClient` for servers
  with TLS 1.2 and 1.3 that answers in TLS 1.2 a client that asks for
  TLS 1.3 but supports Brainpool only with the TLS 1.2 code points, as
  Windows SChannel and OpenSSL before 3.2 do; other clients are not
  affected.
- `examples/fachdienst`: a TLS server that checks client certificates
  against the TSL with OCSP. It passes gematik's PKI test suite 8.1.0 as
  a KIM Fachdienst (111 of 111 tests); `scripts/run-pkits.sh` runs the
  suite against it.

**Fixes:**

- `ti.Verifier` and `tlsutil.ChainVerifier` reject a certificate with a
  critical extension that `crypto/x509` doesn't process (RFC 5280,
  Section 4.2; gemSpec_PKI GS-A_4661-01). Before, such certificates were
  accepted.
- `tlsutil.ChainVerifier` checks the path length constraints of
  intermediate and root certificates.
- `ti.Verifier` picks the issuing CA by authority key identifier as well
  as by name, when both certificates carry key identifiers; a
  certificate whose identifier matches no trusted CA of that name fails
  with an error that says so.
- `ti.Verifier`'s error for missing key usages names them
  (`lacks key usage keyEncipherment`) instead of printing a hex dump.

**Overlay:** the patches' tests that need a hook skip in FIPS 140-3
mode, where the hooks are off (`GOFIPS140=latest go test crypto/tls`
failed 20 of them before); CI runs the overlay's standard library tests
in that mode too. No change to the patched code.

**Tests:** `scripts/fetch-gemlibpki.sh` also downloads GemLibPki's test
TSLs and their trust anchor; `tsl.TestGemLibPki` verifies them (and
rejects the broken ones) in CI. New fuzz targets: `ocsp:FuzzParseResponse`,
`tsl:FuzzParse`, `internal/xmldsig:FuzzCanonicalize`.
`scripts/fetch-tsl-corpus.sh` and `tsl.TestTSLCorpus` check `tsl`
against 136 production, reference and test TSLs archived since 2025-04
and the TSLs shipped with ZETA Guard (CI); the nightly job checks
today's reference and test TSLs too. `scripts/fetch-tlsfuzzer.sh` and
`interop.TestF1`–`TestF6` run tlsfuzzer's Brainpool and ECDSA scripts
against ivory servers (CI job `tlsfuzzer`). New interop tests S1–S7
against Windows SChannel through .NET's `SslStream` (CI jobs
`schannel-peer`, `schannel`): Brainpool works in TLS 1.2 in both
roles; SChannel's TLS 1.3 uses the TLS 1.2 group code points instead of
RFC 8734's and doesn't interoperate. S5 and `interop.TestI17TLS12Fallback`
(OpenSSL 3.0) check `tlsutil.TLS12Fallback`; S6 and S7 show that a Go
client needs `MaxVersion` TLS 1.2 towards a Windows server with a
Brainpool identity.
`brainpool` checks the ECDH test vectors of RFC 7027 (repeated in RFC
8734) and RFC 6932 and Botan's Brainpool vectors for point
multiplication and deterministic ECDSA (RFC 6979, SHA-1 to SHA-512);
all passed without a code change.
`scripts/fetch-production-tsl.sh` and `tsl.TestProductionTSL` (nightly)
verify the current production TSL against its trust anchor GEM.TSL-CA3,
whose fingerprint the script pins. The workflow `pkits.yml` runs
gematik's PKI test suite on demand.
`ti.TestGemLibPki` checks `ti.Verifier` against certificates
of gematik's TI test PKI as published with gematik's reference library
GemLibPki: its valid and invalid SMC-B certificates, an
Anwendungskonnektor, HBA and eGK identities (brainpoolP256r1), a NIST
P-256 and an RSA identity. `scripts/fetch-gemlibpki.sh` downloads them
(pinned commit, SHA-256 sums); CI runs the test for both profiles.
Interop with BouncyCastle's JSSE provider: B6 (a server with an RSA and
a Brainpool identity, Go clients with RSA or Brainpool client
certificates) and B7 (two connections in a row with the `ti` session
helpers: BouncyCastle 1.86 and Go never resume each other's sessions, and
both connections succeed with full handshakes). B8: the TLS client of
gematik's PKI test suite (its BouncyCastle settings, including the named
groups as it writes them) against `ti.ServerConfig` and `ti.KTServer`.

**Documentation:** `docs/compliance.md` has a section on gematik's PKI
test suite: what its TLS client does, what ivory covers, and what a
server product must add (TSL, OCSP with Brainpool-signed responses).

**CI:** the GitHub Actions moved to their Node.js 24 releases
(checkout v7, setup-go v7, cache v6, setup-java v6, upload-artifact
v7), still pinned by commit hash. `fuzz.yml` takes a `targets` input to
run only some fuzz targets.

## v0.1.0

First public release.

**Go release:** go1.27.2 (profiles `core` and `kt`).

**Overlay** (patches to `crypto/x509` and `crypto/tls`):

- P0: a TLS server refuses renegotiation with a fatal `no_renegotiation`
  alert.
- P1: `crypto/x509` parses certificates and CSRs whose key is on a named
  curve it doesn't implement, with `PublicKeyAlgorithm =
  UnknownPublicKeyAlgorithm`; `Verify` results are unchanged.
  `GODEBUG=x509unknowncurve=0` restores the old error.
- P2: `Config.VerifyUnsupportedSignature` verifies peer signatures by
  keys `crypto/tls` doesn't support (TLS 1.2 and 1.3).
- P3: `crypto/tls` signs with keys of public-key types it doesn't know,
  as listed in `Certificate.SupportedSignatureAlgorithms`; TLS 1.3
  signers implement `crypto.MessageSigner` and get
  `*tls.SignatureSchemeOptions`.
- P4: `Config.KeyExchanges` adds external key-exchange groups (TLS 1.2
  ECDHE and TLS 1.3 key shares, HelloRetryRequest included).
- P5 (provisional API): `Config.SignatureSchemes` sets the advertised
  signature schemes, including ones `crypto/tls` doesn't implement.
- P6, P7 (profile `kt` only): one CertificateRequest certificate type per
  suite; a client offers ECDSA suites before RSA suites.

**Library:**

- `brainpool`: brainpoolP256r1, P384r1 and P512r1 in constant time:
  key generation, ECDSA (hedged RFC 6979 nonces, DER and raw r‖s), ECDH,
  and KEM adapters for `tls.KeyExchange`.
- `x509util`: Brainpool keys in PKIX, PKCS #8 and SEC 1; certificate,
  CSR and CRL signatures by Brainpool keys.
- `tlsutil`: the Brainpool groups and signature schemes for `crypto/tls`,
  `VerifyUnsupportedSignature`, signers for software keys and smart cards
  (`NewSigner`, `RawSigner`, `Certificate`, `X509KeyPair`), certificate
  selection by the client's groups, `ChainVerifier`.
- `ti`: TLS 1.2 presets for TI roles (`ServerConfig`, `ClientConfig`,
  `ConnectorClientConfig`, `KTServer`), the TI certificate check
  (`Verifier`, with CRLs), session ticket and client cache helpers with a
  24-hour limit.

**Tests:** Go's `crypto/x509` and `crypto/tls` suites under the overlay,
BoGo, x509-limbo and NIST PKITS; Wycheproof and gemSpec_Krypt vectors;
interop with OpenSSL 3.0 and 3.5 and BouncyCastle's JSSE provider 1.86
(TLS 1.2 and 1.3, both roles).

**Tools:** `cmd/ivory-overlay` (run through `scripts/ivory-overlay`):
`toolchain`, `pin`, `build`, `materialize`, `env`, `doctor`, `stdtest`,
`bogo`, `tipcheck`, `latest`, `adopt`.
