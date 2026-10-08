# Changelog

ivory follows [semantic versioning](https://semver.org/). Before v1.0.0,
a minor version may change APIs. Each version supports one Go release
(README.md, "Supported Go versions"); a new Go patch release gives a new
ivory patch version.

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
