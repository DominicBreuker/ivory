# TI requirements: mechanism and tests

This matrix maps the requirements of the German health care telematics
infrastructure (TI) that concern a TLS stack and Brainpool cryptography
to the part of ivory that meets them, and to the tests that check it. It
is evidence for a product's own conformity work, not a statement of
conformity: products are evaluated, libraries aren't.

Sources: gemSpec_Krypt V2.51.0 (unless noted), gemSpec_KT V3.17.1,
gemSpec_PKI V2.28.0, BSI TR-03116-1 V3.20. Requirement IDs carry their
revision. Short quotes are verbatim.

**Mechanisms:** P0–P7 are the overlay patches (README.md, "Patches"); P6
and P7 exist only in the profile `kt`. Package names refer to this
module.

**Tests:** "Go tree" tests are added to `crypto/tls` or `crypto/x509` by
the patch and run with `ivory-overlay stdtest`. `I`*n* are the interop
tests in `interop/` (Go against OpenSSL, and Go against Go), `B`*n* those
against BouncyCastle's TLS provider for Java, `K`*n* the
wire probes in `probe/`, H4 the test in `interop/h4`. BoGo is BoringSSL's
TLS test suite, run with `ivory-overlay bogo`.

Status: **met** (mechanism and test exist), **met (kt)** (only with
profile `kt`), **partly** (see the note), **product** (the product must
do or show it).

## TLS versions and cipher suites

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_4385 (MUSS), A_18464 (DARF NICHT) | TLS 1.2; not TLS 1.1 or older | `ti` presets: `MinVersion` = `MaxVersion` = TLS 1.2 | `ti.TestKTServer` (negotiated version), I1–I12 | met |
| A_18467 (KANN), A_17322 (MUSS) | TLS 1.3 only with BSI TR-02102-2 configurations | `ti` presets stay on TLS 1.2: a Go TLS 1.3 client always offers ChaCha20-Poly1305 | K2 (`probe.TestK2TLS13CipherSuites` records the offer), K7 | met by staying on TLS 1.2 |
| GS-A_4384-03 (MUSS) | TLS_ECDHE_RSA_WITH_AES_128/256_GCM; ECDHE on P-256 and P-384 (MUSS), brainpoolP256r1 and brainpoolP384r1 (SOLL); "Andere Kurven … DÜRFEN NICHT verwendet werden" | `ti` presets: `CipherSuites`, `CurvePreferences` = `ti.Curves` (P-256, P-384, 26, 27); P4 with `tlsutil.KeyExchanges` | I12 (`TestI12SupportedGroups`), K4, I1–I3 | met |
| A_17124-03 (MUSS) | ECDHE_ECDSA_WITH_AES_128/256_GCM with an ECC identity; same curves; a client puts the ECDSA suites first in `cipher_suites` (item 3) | P1–P4 for the ECC identity; item 3: P7 | I1–I5; P7: Go tree `TestECDSASuitesFirst`, I11, K1 | met; item 3: met (kt) |
| A_17089-03 (MUSS, KT) | RSA and/or ECDSA identity of the gSMC-KT; with both, all four suites | `ti.KTServer` (both identities, chosen by `tlsutil.GetCertificate`); P3 | `ti.TestKTServer`, I6, `examples/ktserver` | met |
| A_17094-02 (MUSS, Konnektor) | ECDSA suites; P-256, P-384, brainpoolP256r1 and brainpoolP384r1; ECDSA suites first | `ti.ConnectorClientConfig`; P4; P7 for the order | I11, I12, `examples/connectorclient` | met; order: met (kt) |
| A_22450 (MUSS, gemSpec_KT) | the KT uses one of the A_17089 suites | `ti.KTServer` suites per identity | `ti.TestKTServer` | met |
| A_22451 (MUSS) | `handshake_failure` without an acceptable suite | Go's `crypto/tls` | none in ivory | met by Go (not tested here) |

## Identities and certificates in the handshake

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_4359-02 (MUSS) | X.509 identities for TLS authentication: the algorithms of Tab_KRYPT_002, and of Tab_KRYPT_002a for ECDSA identities | P1 (parse), P2 (verify peer signatures: `tlsutil.VerifyUnsupportedSignature`), P3 (sign: `tlsutil.NewSigner`, `RawSigner`, `Certificate`) | Go tree: P1 `TestParseCertificateUnsupportedCurve*`, P2 `TestVerifyUnsupportedSignature*`, P3 `TestOpaqueKey*`; I1–I5, I13–I16, B1–B3 | met |
| A_22453 (MUSS) | ECDSA suite → ECC identity, RSA suite → RSA identity | P3 (suite selection by signature type); `tlsutil.GetCertificate` | `ti.TestKTServer` ("ECDSA suites only", "RSA suites only"), I6, B4; Go tree `TestOpaqueKeyCertificateSelection` | met |
| A_22454 (MUSS) | CertificateRequest `certificate_types` with "genau ein Element": `ecdsa_sign` on ECDSA suites, `rsa_sign` on RSA suites | P6 | Go tree `TestCertificateRequestTypes`, I10, K3 | met (kt) |
| A_22455 (MUSS) | no Certificate message: abort; an empty list, an unknown CA or the wrong key type: continue | `ti.KTServer`: `RequestClientCert`, P1+P2 for Brainpool client keys, `VerifyConnection` reports the state instead of failing | `ti.TestKTServer`; Go tree `TestVerifyUnsupportedSignatureClientCertificate`, `…NoClientCertificate` | met |
| A_22456 (MUSS, gemSpec_KT) | the states of the SICCT TLS channel | `ti.KTServer.OnState` with `ti.State` | `ti.TestKTServer`, `examples/ktserver` | met |
| A_22888, A_22889 (MUSS, gemSpec_KT) | find the issuing CA among the stored CA certificates; the list of allowed CAs | `ti.Verifier` (two levels, no path building), `ti.KonnektorVerifier` | `ti.TestVerifier`, `ti.TestKTServer` | met |
| A_22890 (MUSS, gemSpec_KT) | the handshake succeeds with an empty certificate list, or a valid certificate and successful authentication | `ti.KTServer` | `ti.TestKTServer` ("no client certificate (A_22890)"), `examples/ktserver` | met |
| A_21275-01 (MUSS) | only SHA-256/384/512 or SHA3-256/384/512 in handshake signatures | Go ≥ 1.25 (`tlssha1=0` by default); `tlsutil.VerifyUnsupportedSignature` and `x509util.CheckSignature` reject SHA-1 | I8 (`TestI8NoSHA1`), `tlsutil.TestVerifyUnsupportedSignature` ("SHA-1") | met; the product must not set `GODEBUG=tlssha1=1` |

## Key exchange

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| A_23912 (KANN), A_23913 (MUSS) | VSDM servers may offer only Brainpool groups; the Intermediär supports brainpoolP256r1 and brainpoolP384r1 | P4 (`Config.KeyExchanges`) with `tlsutil.KeyExchanges` | I2 (Brainpool group only), I3, H4 (`TestH4BrainpoolOnly`); Go tree `TestKeyExchange*` | met |
| GS-A_4384-03, A_17094-02 | Brainpool groups 26 and 27 offered by clients | P4 | I3, I12, K4 | met |
| (TLS 1.3, RFC 8734) | groups 31–33, HelloRetryRequest | P4 (TLS 1.3 key shares) | I13, I14, I15/I16 (OpenSSL 3.5.4); Go tree `TestKeyExchangeTLS13` | met (not a TI requirement) |

## Renegotiation and sessions

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_5524 (MUSS) | the KT refuses renegotiation "mit einem „no_renegotiation“-Alert" | P0 | Go tree `TestServerRejectsRenegotiation`; BoGo `Renegotiate-Server-Forbidden`; I9, K5, `examples/ktserver` `TestKTServerRenegotiation` | met |
| GS-A_5322 (MUSS) | key material from the key exchange, and everything derived from it, "sicher gelöscht" after at most 24 hours; ticket keys changed at least every 48 hours; renegotiation only per RFC 5746 or refused | `ti` server presets disable tickets; `ti.SessionTickets` (rotation, 24 h limit); `ti.NewClientSessionCache` (24 h); fresh ephemeral keys per handshake (`tlsutil.KeyExchanges`) | `ti.TestSessionResumption` | partly: lifetimes are met; erasure can't be guaranteed in Go (security.md, Section 4) — product |

## Keys, signatures and certificates outside TLS

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_4357-02 (MUSS), Tab_KRYPT_002a | ECDSA with SHA-256/384/512 on the Brainpool curves | `brainpool` (ECDSA), `x509util.CheckSignature`, `CheckCertificateSignatureFrom` | `brainpool.TestWycheproofECDSA`, `TestOpenSSLSignatures`, `TestGemSpecRCA3`; `x509util.TestCheckSignature`, `TestCheckCertificateSignatureFrom*` | met |
| A_23511 (MUSS) | ECC keys in the "named-curve" encoding | `x509util.ParseECPrivateKey`, `ParsePKIXPublicKey` reject explicit parameters | `x509util.TestParseECPrivateKeyInvalid`, `TestParsePKIXPublicKeyInvalid` | met |
| GS-A_4939 (MUSS, gemSpec_PKI) | CRL signer certificates (C.GEM.CRL) with cA = FALSE and keyUsage cRLSign | `x509util.CheckCRLSignatureFrom`; `ti.CRL.Signer` | `x509util.TestCheckCRLSignatureFrom*`, `ti.TestVerifier` | met |
| A_20161-01, A_23463 (MUSS) | ECIES examples of the specification (brainpoolP256r1 ECDH) | `brainpool` (ECDH) | `brainpool.TestGemSpecA20161`, `TestGemSpecA23463` | ECDH reproduced; ECIES itself is not in ivory |
| TR-03116-1 V3.20, 3.8 and 3.9 | RNG for keys at least DRG.3 or PTG.2 | `crypto/rand` (`getrandom(2)` on Linux) | none | product (security.md, Section 3) |

## Not covered

- Requirements on OCSP, TSL processing, certificate creation, ECIES,
  card-verifiable certificates, JOSE and PACE: not in ivory yet.
- Product-level duties: configuration, logging of the A_22456 states,
  storage of the CA certificates (A_22889), key storage, RNG evidence,
  erasure.
