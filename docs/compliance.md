# TI requirements: mechanism and tests

This matrix maps the requirements of the German health care telematics
infrastructure (TI) that concern a TLS stack, Brainpool cryptography,
the TSL and OCSP to the part of ivory that meets them, and to the tests that check it. It
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
TLS test suite, run with `ivory-overlay bogo`. "PKI test suite" is
gematik's, run against `examples/fachdienst` with
`scripts/run-pkits.sh` (last section).

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
| GS-A_5322 (MUSS) | key material from the key exchange, and everything derived from it, "sicher gelöscht" after at most 24 hours; ticket keys changed at least every 48 hours; renegotiation only per RFC 5746 or refused | `ti` server presets disable tickets; `ti.SessionTickets` (rotation, 24 h limit); `ti.NewClientSessionCache` (24 h); fresh ephemeral keys per handshake (`tlsutil.KeyExchanges`) | `ti.TestSessionResumption`; B7 (BouncyCastle peers don't resume with Go: full handshakes) | partly: lifetimes are met; erasure can't be guaranteed in Go (security.md, Section 4) — product |

## Keys, signatures and certificates outside TLS

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_4357-02 (MUSS), Tab_KRYPT_002a | ECDSA with SHA-256/384/512 on the Brainpool curves | `brainpool` (ECDSA), `x509util.CheckSignature`, `CheckCertificateSignatureFrom` | `brainpool.TestWycheproofECDSA`, `TestBotanRFC6979`, `TestOpenSSLSignatures`, `TestGemSpecRCA3`; `x509util.TestCheckSignature`, `TestCheckCertificateSignatureFrom*` | met |
| A_23511 (MUSS) | ECC keys in the "named-curve" encoding | `x509util.ParseECPrivateKey`, `ParsePKIXPublicKey` reject explicit parameters | `x509util.TestParseECPrivateKeyInvalid`, `TestParsePKIXPublicKeyInvalid` | met |
| GS-A_4661-01 (MUSS, gemSpec_PKI) | process critical certificate extensions as RFC 5280, Section 4.2 says: reject a certificate with a critical extension that isn't recognized | `ti.Verifier`, `tlsutil.ChainVerifier` | `ti.TestVerifier`, `tlsutil.TestChainVerifierConstraints`, `ti.TestGemLibPki` | met |
| GS-A_4939 (MUSS, gemSpec_PKI) | CRL signer certificates (C.GEM.CRL) with cA = FALSE and keyUsage cRLSign | `x509util.CheckCRLSignatureFrom`; `ti.CRL.Signer` | `x509util.TestCheckCRLSignatureFrom*`, `ti.TestVerifier` | met |
| A_20161-01, A_23463 (MUSS) | ECIES examples of the specification (brainpoolP256r1 ECDH) | `brainpool` (ECDH) | `brainpool.TestGemSpecA20161`, `TestGemSpecA23463` | ECDH reproduced; ECIES itself is not in ivory |
| TR-03116-1 V3.20, 3.8 and 3.9 | RNG for keys at least DRG.3 or PTG.2 | `crypto/rand` (`getrandom(2)` on Linux) | none | product (security.md, Section 3) |

## TSL and OCSP

gemSpec_PKI V2.28.0. "TUC" rows are the use cases of chapter 8; the
error codes are the names the errors of `tsl` and `ocsp` wrap.

| Requirement | Demand | Mechanism | Tests | Status |
|---|---|---|---|---|
| GS-A_4642 (MUSS), TUC_PKI_001 | periodic update of the trust space from the TSL: actuality, signer certificate and its OCSP status (with the responders and address of the TSL in the system), new trust anchors, CA certificates; processing goes on after schema and signature checks | `tsl.Updater` (`Init`, `Update`, `Import`, `Current`) | `tsl.TestUpdater`, `TestUpdaterTrustAnchorChange`; PKI test suite (`TslApprovalTests`, `TslSignerApprovalTests`) | met |
| GS-A_4643 (MUSS), TUC_PKI_013 | import a new trust anchor (TSLServiceCertChange): exactly one, valid at its StatusStartingTime, activated no earlier than that | `tsl.TSL.AnnouncedTrustAnchor`, `tsl.Updater` | `tsl.TestServices`, `TestUpdaterTrustAnchorChange`, `TestGemLibPki`; PKI test suite (`TslTaApprovalTests`) | met |
| GS-A_4646, GS-A_4647 (MUSS), TUC_PKI_017, TUC_PKI_016 | download addresses from PointersToOtherTSL (oid_tsl_p_loc, oid_tsl_b_loc); primary, then backup, each tried four times | `tsl.TSL.PrimaryLocations`, `BackupLocations`; `tsl.Updater.Update` | `tsl.TestUpdater`; PKI test suite | met |
| GS-A_4648 (MUSS), TUC_PKI_019 | hash file first; ID and sequence number of a new TSL; NextUpdate and grace period | `tsl.Updater.Update`, `tsl.TSL.Expired` | `tsl.TestUpdater`; PKI test suite | met |
| GS-A_4649 (MUSS), TUC_PKI_020 | validate the TSL against the schema | `tsl.Parse`: structural check written from the schema of ETSI TS 102 231 V3.1.2 (elements, order, number, attributes, simple types) | `tsl.TestSchema`, `TestGemLibPki` | met for the TSL's elements; not a general XML Schema validator |
| GS-A_4650 (MUSS), TUC_PKI_011 | TSL signer certificate: validity, nonRepudiation, id-tsl-kp-tslSigning, signature by the stored TSL signer CA | `tsl.TSL.Verify` | `tsl.TestVerifySigner` | met |
| GS-A_4651 (MUSS), TUC_PKI_012; GS-A_4371 (gemSpec_Krypt) | XML signature of the TSL (ECDSA brainpoolP256r1 for TSL(ECC-RSA)) | `tsl.TSL.Verify` with `internal/xmldsig`: exclusive canonicalization, enveloped signature, XAdES signed properties; ECDSA (Brainpool, NIST), RSA PKCS #1 v1.5 and PSS | `tsl.TestVerifySignerKeys`, `TestVerifyTampered`, `TestGemLibPki`; `internal/xmldsig.TestC14N`; production TSL(ECC-RSA) of September 2026 verified | met |
| GS-A_4652-02 (MUSS), TUC_PKI_018 | certificate check: validity, key usages, CA from the TSL, signature, CA status in the TSL (step 5), OCSP (step 7), certificate type | `ti.Verifier` with `Status: tsl.TSL.Status(…)` | `tsl.TestStatus`, `examples/fachdienst`; PKI test suite (`CertificateApprovalTests`) | met; roles (TUC_PKI_009, admission) are the product's |
| GS-A_4749-01 (MUSS), TUC_PKI_007 | the certificate type must be one the CA may issue (ExtensionOIDs of its TSL entry) | `tsl.TSL.Status` | `tsl.TestStatus` | met |
| GS-A_4656 (MUSS), TUC_PKI_005 | OCSP address from the CA's TSL entry | `tsl.Service.OCSPLocation` | `tsl.TestStatus` | met |
| GS-A_4657-03 (MUSS), TUC_PKI_006 | OCSP: signer from the TSL, signature, status, CertID, times, certHash (ENFORCE_CERTHASH_CHECK), grace period, timeout, TOLERATE_OCSP_FAILURE | `ocsp.Response.Verify`, `ocsp.Checker`; `tsl.StatusOptions.TolerateOCSPFailure` | `ocsp.TestVerifyErrors`, `TestBrainpoolResponders`, `TestChecker`; PKI test suite (`OcspApprovalTests`) | met |
| GS-A_5215 (MUSS) | tolerance of exactly 37.5 s for producedAt, thisUpdate, nextUpdate | `ocsp.DefaultTolerance` | `ocsp.TestVerifyErrors`; PKI test suite (`OcspToleranceApprovalTests`) | met |
| A_23142-01 (MUSS) | OCSP responses about RSA certificates may be signed by ECC responders | any key type for responder and CA | `ocsp.TestBrainpoolMixed` | met |

## Not covered

- Requirements on certificate creation, ECIES, card-verifiable
  certificates, JOSE and PACE: not in ivory yet. QES checks against the
  BNetzA-VL (TUC_PKI_030, -036) and CRL checks of the Konnektor
  (TUC_PKI_021) aren't either.
- Product-level duties: configuration, logging of the A_22456 states,
  storage of the CA certificates (A_22889), key storage, RNG evidence,
  erasure.

## Approval tests with gematik's PKI test suite

gematik's PKI test suite
([gematik/app-PkiTestsuite](https://github.com/gematik/app-PkiTestsuite),
Apache 2.0) tests the PKI functions of TI server products (Intermediär,
VSDM Fachdienst, VPN-Zugangsdienst, IDP, KIM): certificate checks
(TUC_PKI_018), OCSP (TUC_PKI_006) and the TSL (TUC_PKI_001). It brings
its own test PKI, TSL provider and OCSP responder (mostly
brainpoolP256r1), and connects to the product as a TLS client.

**The suite's TLS client:** BouncyCastle JSSE, TLS 1.2,
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 and
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 only, ECC client certificates
only, the groups brainpoolP256r1, brainpoolP384r1, brainpoolP512r1,
secp256r1 and secp384r1 in that order, and no check of the server's
certificate. A completed handshake counts as "the product accepted the
certificate", a failed one (fatal alert, timeout) as "rejected". So the
product must decide during the handshake, in `VerifyConnection`.
`ti.ServerConfig` negotiates brainpoolP256r1 with it (interop test B8).

**ivory's example server passes the suite:** all 111 tests of
product type KimFachdienst (suite 8.1.0). `examples/fachdienst` uses
`tsl.Updater`, `ti.Verifier` with `tsl.TSL.Status` and `ocsp.Checker`
(see the [user guide](user-guide.md#7-tsl-and-ocsp)). Run the suite
against it with

```sh
scripts/run-pkits.sh /tmp/pkits                  # all tests, about 80 minutes
scripts/run-pkits.sh /tmp/pkits OcspApprovalTests  # one class
```

(Java 17 or later, Maven, OpenSSL; product type `KimFachdienst` by
default, `PKITS_TYPE=KimFachdienstNist` for NIST P-256 client
certificates). The workflow `pkits.yml` does the same on GitHub Actions
when started by hand, and uploads the suite's report. A product built the same way starts from there; it
adds what its product type needs beyond the suite's checks (roles and
admission for an Intermediär, for example).

**Before the approval:** run the suite against the product itself (the
suite's README, "Variant A": `initialTslAndTa.sh` writes the TSL and
trust anchor to import, `checkInitialState.sh` runs a smoke test,
`startApprovalTest.sh` the tests selected in `allTests.txt`; the report
goes to `out/testreport`). The configuration values the suite asks for
(`ocspGracePeriodSeconds`, the producedAt tolerances,
`tslDownloadIntervalSeconds`) must match the product's settings.

eHealth card terminals aren't among the suite's product types: a
terminal stores the CA certificates of the TSL (A_22889) and, without a
connection to an OCSP responder, may check against an empty CRL
(gemSpec_KT V3.17.1, A_22888). `ti.KTServer` also completes the
handshake when the Konnektor's certificate fails the check (A_22890), so
a test that expects a failed handshake doesn't apply to it.
