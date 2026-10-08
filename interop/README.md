# interop: Go with ivory against other TLS stacks

These tests run real handshakes between Go with the ivory overlay and
OpenSSL (`openssl s_server`, `openssl s_client`), BouncyCastle's TLS
provider for Java (BCJSSE), and between two Go peers. They use the test PKI in `../testdata/pki` and need the overlay and
the build tag `ivory`:

```sh
eval "$(scripts/ivory-overlay env -profile core)"
go test -v ./interop/...
```

Tests that need OpenSSL are skipped if `openssl` is missing. The TLS 1.3
tests against OpenSSL (I15, I16) need OpenSSL 3.2 or later, which has the
Brainpool groups and signature schemes of RFC 8734; they run
`$IVORY_OPENSSL3` (default `openssl`) and are skipped if it is older,
unless `IVORY_REQUIRE_TLS13=1` is set. `scripts/build-openssl.sh` builds
a recent OpenSSL from source:

```sh
scripts/build-openssl.sh 3.5.4 967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99 ~/.cache/ivory/openssl-3.5.4
IVORY_OPENSSL3=~/.cache/ivory/openssl-3.5.4/bin/openssl IVORY_REQUIRE_TLS13=1 go test -run 'TestI1[3-6]' ./interop
```

The BouncyCastle tests (B1–B5) need a JDK (11 or later; `java` and
`javac`) and the BouncyCastle jars, which `scripts/fetch-bouncycastle.sh`
downloads from Maven Central and checks against pinned SHA-256 sums. The
peer is [testdata/bcpeer/BCPeer.java](testdata/bcpeer/BCPeer.java). The
tests are skipped without `IVORY_BCJARS`, unless `IVORY_REQUIRE_BC=1` is
set:

```sh
scripts/fetch-bouncycastle.sh ~/.cache/ivory/bouncycastle
IVORY_BCJARS=~/.cache/ivory/bouncycastle IVORY_REQUIRE_BC=1 go test -run 'TestB[1-9]' ./interop
```

## Matrix

"bP256" is brainpoolP256r1. Groups 26–28 are the Brainpool groups of TLS
1.2 (RFC 7027), 31–33 those of TLS 1.3 (RFC 8734).

| ID | Test | Scenario | Expected |
|---|---|---|---|
| I1 | `TestI1GoServerOpenSSLClient` | Go server with a bP256 certificate, requiring a client certificate; OpenSSL client with a bP256 certificate, groups `P-256:brainpoolP256r1` | ECDHE on P-256, both sides authenticated with Brainpool keys |
| I2 | `TestI2GoServerOpenSSLClientBrainpoolGroup` | as I1, OpenSSL client offers only `brainpoolP256r1` | group 26 with `Config.KeyExchanges`; no common group without it |
| I3 | `TestI3GoClientOpenSSLServer` | Go client with a bP256 client certificate; OpenSSL server requiring client certificates, groups `P-256:brainpoolP256r1` and `brainpoolP256r1` | success in both cases, also when the client offers TLS 1.2 and 1.3; without `Config.KeyExchanges` the client offers no Brainpool group and OpenSSL can't use its Brainpool certificate ("no shared cipher") |
| I4 | `TestI4GoGo` | Go ↔ Go, mutual authentication, bP256/384/512 | success |
| I5 | `TestI5OtherCurves` | I1–I3 with brainpoolP384r1 and brainpoolP512r1 | success |
| I6 | `TestI6TwoIdentities` | KT server (`ti.KTServer`) with an RSA and a Brainpool identity; OpenSSL client with only ECDSA suites, then only RSA suites | Brainpool certificate on ECDSA suites, RSA certificate on RSA suites (A_22453) |
| I7 | `TestI7Negative` | N1: the server signs with another key than its certificate's; N2: a chain from a CA with the same name but another key; N3: a Brainpool peer without `VerifyUnsupportedSignature`; an expired certificate | every handshake fails |
| I8 | `TestI8NoSHA1` | OpenSSL peers that prefer or offer only SHA-1 signature schemes | SHA-1 is never used (A_21275-01) |
| I9 | `TestI9Renegotiation` | OpenSSL client renegotiates against a Go server | fatal `no_renegotiation` alert (GS-A_5524) |
| I10 | `TestI10CertificateTypes` | CertificateRequest `certificate_types` seen by OpenSSL | core: `rsa_sign, ecdsa_sign`; kt: one type, matching the suite (A_22454) |
| I11 | `TestI11SuiteOrder` | cipher suites in the ClientHello of `ti.ConnectorClientConfig`, seen by OpenSSL | core: Go's order (C02B, C02F, C02C, C030); kt: ECDSA suites first (A_17124-03) |
| I12 | `TestI12SupportedGroups` | `supported_groups` of the `ti` presets, seen by OpenSSL | only P-256, P-384, 26, 27 (GS-A_4384-03) |
| I13 | `TestI13GoGoTLS13` | Go ↔ Go TLS 1.3, mutual, bP256/384/512, groups 31–33 only | success with schemes 0x081A–0x081C |
| I14 | `TestI14HelloRetryRequest` | TLS 1.3 client sends a P-256 key share, server accepts only group 31; also with `tlsutil.GetCertificate` | HelloRetryRequest, then group 31 |
| I15 | `TestI15GoClientOpenSSLServerTLS13` | Go client ↔ OpenSSL ≥ 3.2 `s_server -tls1_3`, three curves, with and without HelloRetryRequest | success |
| I16 | `TestI16GoServerOpenSSLClientTLS13` | Go server ↔ OpenSSL ≥ 3.2 `s_client -tls1_3`, three curves, with and without HelloRetryRequest | success |
| – | `h4.TestH4`, `TestH4BrainpoolOnly` | a TLS 1.2 server built without patch P4 (no `Config.KeyExchanges`) against an OpenSSL client with a Brainpool certificate | success if the client also offers P-256; no common group if it offers only Brainpool groups |

### BouncyCastle (BCJSSE 1.86)

| ID | Test | Scenario | Expected |
|---|---|---|---|
| B1 | `TestB1GoServerBCClient` | Go server with a Brainpool certificate, requiring a client certificate; BouncyCastle client with a Brainpool certificate, TLS 1.2, bP256/384/512; the client offers only the Brainpool group, or P-256 first | Brainpool group 26–28, or P-256 |
| B2 | `TestB2GoClientBCServer` | Go client with a Brainpool client certificate; BouncyCastle server requiring client certificates, TLS 1.2, Brainpool groups only, bP256/384/512 | Brainpool group 26–28 |
| B3 | `TestB3TLS13` | TLS 1.3 in both roles, mutual, bP256/384/512, groups 31–33 only | success with schemes 0x081A–0x081C |
| B4 | `TestB4KTServerBCClient` | KT server (`ti.KTServer`, RSA and Brainpool identity) against a BouncyCastle client with a Brainpool certificate, like a Konnektor; only ECDSA suites, then only RSA suites | Brainpool identity on ECDSA suites, RSA identity on RSA suites (A_22453); kt: on RSA suites the client sends no certificate and the handshake goes on (A_22454, A_22890) |
| B5 | `TestB5ConnectorClientBCServer` | Konnektor-like Go client (`ti.ConnectorClientConfig`) against a BouncyCastle server with a Brainpool identity requiring client certificates, like a card terminal | success |

Expectations that differ by overlay profile follow the build tag
`ivory_kt`, which `ivory-overlay env -profile kt` sets.

OpenSSL in TLS 1.2 refuses an ECDSA certificate whose curve the peer
didn't list in `supported_groups` ("wrong curve"), in both directions. So
Go clients with Brainpool certificates need `Config.KeyExchanges`, and
the OpenSSL peers in these tests offer the Brainpool groups.
