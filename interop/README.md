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

The BouncyCastle tests (B1–B8) need a JDK (11 or later; `java` and
`javac`) and the BouncyCastle jars, which `scripts/fetch-bouncycastle.sh`
downloads from Maven Central and checks against pinned SHA-256 sums. The
peer is [testdata/bcpeer/BCPeer.java](testdata/bcpeer/BCPeer.java). The
tests are skipped without `IVORY_BCJARS`, unless `IVORY_REQUIRE_BC=1` is
set:

```sh
scripts/fetch-bouncycastle.sh ~/.cache/ivory/bouncycastle
IVORY_BCJARS=~/.cache/ivory/bouncycastle IVORY_REQUIRE_BC=1 go test -run 'TestB[1-9]' ./interop
```

The tlsfuzzer tests (F1–F6) need a tlsfuzzer checkout and a Python
virtual environment with tlslite-ng, which `scripts/fetch-tlsfuzzer.sh`
sets up (pinned commit, packages pinned by SHA-256). They are skipped
without `IVORY_TLSFUZZER`, unless `IVORY_REQUIRE_TLSFUZZER=1` is set:

```sh
scripts/fetch-tlsfuzzer.sh ~/.cache/ivory/tlsfuzzer
IVORY_TLSFUZZER=~/.cache/ivory/tlsfuzzer IVORY_REQUIRE_TLSFUZZER=1 go test -run 'TestF[1-6]' ./interop
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
| I10 | `TestI10CertificateTypes` | CertificateRequest `certificate_types` and `supported_signature_algorithms` seen by OpenSSL | core: `rsa_sign, ecdsa_sign` and crypto/tls's schemes; kt: one type, matching the suite (A_22454), and only the schemes of that type |
| I11 | `TestI11SuiteOrder` | cipher suites in the ClientHello of `ti.ConnectorClientConfig`, seen by OpenSSL | core: Go's order (C02B, C02F, C02C, C030); kt: ECDSA suites first (A_17124-03) |
| I12 | `TestI12SupportedGroups` | `supported_groups` of the `ti` presets, seen by OpenSSL | only P-256, P-384, 26, 27 (GS-A_4384-03) |
| I13 | `TestI13GoGoTLS13` | Go ↔ Go TLS 1.3, mutual, bP256/384/512, groups 31–33 only | success with schemes 0x081A–0x081C |
| I14 | `TestI14HelloRetryRequest` | TLS 1.3 client sends a P-256 key share, server accepts only group 31; also with `tlsutil.GetCertificate` | HelloRetryRequest, then group 31 |
| I15 | `TestI15GoClientOpenSSLServerTLS13` | Go client ↔ OpenSSL ≥ 3.2 `s_server -tls1_3`, three curves, with and without HelloRetryRequest | success |
| I16 | `TestI16GoServerOpenSSLClientTLS13` | Go server ↔ OpenSSL ≥ 3.2 `s_client -tls1_3`, three curves, with and without HelloRetryRequest | success |
| I17 | `TestI17TLS12Fallback` | Go server for TLS 1.2 and 1.3 with only a bP256 identity; OpenSSL `s_client` offering TLS 1.2 and 1.3 with Brainpool groups; `tlsutil.TLS12Fallback` | OpenSSL < 3.2 (Brainpool only as 26–28, no 0x081A–0x081C): fails without the fallback, TLS 1.2 with it; OpenSSL ≥ 3.2 (`$IVORY_OPENSSL3`): TLS 1.3 on group 31 with the fallback on |
| – | `h4.TestH4`, `TestH4BrainpoolOnly` | a TLS 1.2 server built without patch P4 (no `Config.KeyExchanges`) against an OpenSSL client with a Brainpool certificate | success if the client also offers P-256; no common group if it offers only Brainpool groups |

### BouncyCastle (BCJSSE 1.86)

| ID | Test | Scenario | Expected |
|---|---|---|---|
| B1 | `TestB1GoServerBCClient` | Go server with a Brainpool certificate, requiring a client certificate; BouncyCastle client with a Brainpool certificate, TLS 1.2, bP256/384/512; the client offers only the Brainpool group, or P-256 first | Brainpool group 26–28, or P-256 |
| B2 | `TestB2GoClientBCServer` | Go client with a Brainpool client certificate; BouncyCastle server requiring client certificates, TLS 1.2, Brainpool groups only, bP256/384/512 | Brainpool group 26–28 |
| B3 | `TestB3TLS13` | TLS 1.3 in both roles, mutual, bP256/384/512, groups 31–33 only | success with schemes 0x081A–0x081C |
| B4 | `TestB4KTServerBCClient` | KT server (`ti.KTServer`, RSA and Brainpool identity) against a BouncyCastle client with a Brainpool certificate, like a Konnektor; only ECDSA suites, then only RSA suites | Brainpool identity on ECDSA suites, RSA identity on RSA suites (A_22453); kt: on RSA suites the client sends no certificate and the handshake goes on (A_22454, A_22890) |
| B5 | `TestB5ConnectorClientBCServer` | Konnektor-like Go client (`ti.ConnectorClientConfig`) against a BouncyCastle server with a Brainpool identity requiring client certificates, like a card terminal | success |
| B6 | `TestB6MixedIdentitiesBCServer` | BouncyCastle server with an RSA and a Brainpool identity, trusting an RSA and a Brainpool CA, requiring client certificates; Go clients with an RSA or a Brainpool client certificate, on an ECDSA or an RSA suite | the server's identity follows the suite; both client key types are accepted with either |
| B7 | `TestB7SessionResumption` | two connections in a row: Go server with `ti.SessionTickets` and a BouncyCastle client, and Go client with `ti.NewClientSessionCache` and a BouncyCastle server; TLS 1.2 and 1.3 | both connections succeed with full handshakes: BouncyCastle 1.86 resumes TLS 1.2 sessions by session ID only, Go by ticket or PSK only |
| B8 | `TestB8PkiTestsuiteClient` | the TLS client of gematik's PKI test suite (8.1.0) against `ti.ServerConfig` and `ti.KTServer`: TLS 1.2, the two ECDHE-ECDSA AES-GCM suites, a Brainpool client certificate, `jdk.tls.namedGroups` = "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp256r1, secp384r1" (with spaces); then a client certificate from a CA the server doesn't trust | the client offers the five groups in that order; brainpoolP256r1 (the client's first group), an ECDSA suite, the Brainpool identity; `ti.ServerConfig` rejects the unknown CA in the handshake with a `bad_certificate` alert |

### tlsfuzzer

tlsfuzzer sends hand-crafted and malformed handshakes to an ivory server
and checks its answers and alerts. Where ivory deliberately answers
differently than a script expects, the probe is an expected failure
with the message it must fail with, so that a change either way fails
the test.

| ID | Test | Script | Expected |
|---|---|---|---|
| F1 | `TestF1TLS13BrainpoolKeyShares` | `test-tls13-ecdhe-brainpool-curves.py` against a TLS 1.3 server with groups 31–33, and against a TLS 1.2 and 1.3 server with `tlsutil.TLS12Fallback` | malformed key shares (padded, truncated, from another curve, point at infinity, off the curve, x = y = 0) end with `illegal_parameter`; all 23 probes pass, with the fallback too (an RFC 8734 client keeps TLS 1.3) |
| F2 | `TestF2TLS13BrainpoolCertificateVerify` | `test-tls13-ecdsa-brainpool-in-certificate-verify.py`, TLS 1.3 client certificates on bP256/384/512 | the key's scheme works; fuzzed signatures, TLS 1.2 schemes and NIST schemes are refused; a Brainpool scheme of another curve is refused with `decrypt_error` where tlsfuzzer expects `illegal_parameter` (crypto/tls leaves Brainpool keys to `Config.VerifyUnsupportedSignature`, whose errors end with `decrypt_error`) |
| F3 | `TestF3ECDSASignatureFlexibility` | `test-ecdsa-sig-flexibility.py` against TLS 1.2 servers with bP256/384/512 identities and `ti.ServerConfig` | ServerKeyExchange signed with SHA-256, -384 or -512 as the client asks; a client with only SHA-1 or SHA-224 gets `handshake_failure` (A_21275-01); a TLS 1.2 client with only a TLS 1.3 Brainpool scheme is refused after ServerHello, since crypto/tls picks the scheme when it writes ServerKeyExchange |
| F4 | `TestF4TLS12CertificateVerify` | `test-ecdsa-in-certificate-verify.py`, TLS 1.2 client certificates on bP256/384/512 | SHA-256, -384, -512 work; MD5, mismatched hashes and the TLS 1.3 schemes are refused; a CertificateVerify naming SHA-1 or SHA-224 gets `illegal_parameter` (the server never offers them); both profiles |
| F5 | `TestF5TLS13ServerCertificates` | `test-tls13-ecdsa-support.py` against a TLS 1.3 server with bP256, bP384, bP512 and P-256 identities (`tlsutil.GetCertificate`) | each scheme gets its identity; SHA-1 and SHA-224 fail; the P-384 and P-521 probes are skipped (no such identities in the test PKI) |
| F6 | `TestF6KTCertificateRequest` | `test-certificate-request.py` against `ti.KTServer` on an ECDSA suite with a Brainpool client certificate | core: `rsa_sign, ecdsa_sign` and crypto/tls's schemes without SHA-1; kt: only `ecdsa_sign` (A_22454) and only its schemes (ECDSA, Ed25519), so tlsfuzzer's check that the two lists agree passes |

### Windows SChannel (.NET SslStream)

Windows' TLS stack, as .NET's `SslStream` uses it, against Go with the
overlay, on GitHub's `windows-2025` runner (Windows Server 2025, build
26100; CI jobs `schannel-peer` and `schannel`). The Go peer
[testdata/schannel/gopeer](testdata/schannel/gopeer) is cross-compiled
with the overlay; the .NET peer is
[testdata/schannel/SChannelPeer](testdata/schannel/SChannelPeer);
[testdata/schannel/run.ps1](testdata/schannel/run.ps1) runs them with
client authentication on bP256, bP384 and bP512 identities and checks
the results. SChannel's Brainpool groups are off by default:
[enable-brainpool.ps1](testdata/schannel/enable-brainpool.ps1) puts them
first in the ECC curve order (the runner image sets the order by group
policy, which overrides `Enable-TlsEccCurve`; no reboot needed).

| ID | Scenario | Expected |
|---|---|---|
| S1 | Go server (Brainpool groups only), SChannel client, TLS 1.2 | success: SChannel offers 26, 27, 28 first; group 26; SChannel signs CertificateVerify with 0x0403 on every Brainpool curve, which `tlsutil.VerifyUnsupportedSignature` verifies |
| S2 | Go client, SChannel server, TLS 1.2 | success: SChannel picks group 28 and signs with 0x0403 |
| S3 | Go server, SChannel client, TLS 1.3 | fails: SChannel offers the Brainpool groups as 26–28 in TLS 1.3, not RFC 8734's 31–33, and none of the schemes 0x081A–0x081C |
| S4 | Go client, SChannel server, TLS 1.3 | fails: SChannel rejects the ClientHello with groups 31–33 ("no common algorithm", `protocol_version` alert) |
| S5 | Go server for TLS 1.2 and 1.3, SChannel client with the system's protocols (TLS 1.2 and 1.3) | without `tlsutil.TLS12Fallback`: fails (TLS 1.3 is chosen, and the Brainpool identity can't be used in it); with it: TLS 1.2 on a Brainpool group |
| S6 | Go client for TLS 1.2 and 1.3, SChannel server with the system's protocols | fails: SChannel picks TLS 1.3, has no algorithm for its Brainpool certificate there ("no common algorithm") and doesn't fall back to TLS 1.2 (`protocol_version` alert) |
| S7 | Go client for TLS 1.2 only, SChannel server with the system's protocols | TLS 1.2 on a Brainpool group: a client must be configured for TLS 1.2 towards Windows servers with Brainpool identities |

S3 and S4 are pinned: if SChannel starts to speak RFC 8734, `run.ps1`
fails and the expectations must change. S5 shows what the opt-in
`tlsutil.TLS12Fallback` is for. Allowing groups 26–28 in TLS
1.3 on the Go side (`gopeer -tls13-legacy-groups`) doesn't help:
SChannel then still offers no signature scheme for a Brainpool
certificate that RFC 8446 allows.

Expectations that differ by overlay profile follow the build tag
`ivory_kt`, which `ivory-overlay env -profile kt` sets.

OpenSSL in TLS 1.2 refuses an ECDSA certificate whose curve the peer
didn't list in `supported_groups` ("wrong curve"), in both directions. So
Go clients with Brainpool certificates need `Config.KeyExchanges`, and
the OpenSSL peers in these tests offer the Brainpool groups.
