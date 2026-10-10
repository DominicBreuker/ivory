// Package tsl reads and verifies the trust-service status list (TSL) of
// the German health care telematics infrastructure (TI), whose XML
// signature the TSL service makes with brainpoolP256r1 (TSL(ECC-RSA)) or
// RSA, and connects it to certificate checks.
//
// Parse reads a TSL and checks it against the XML schema of ETSI TS 102
// 231 (gemSpec_PKI V2.28.0, TUC_PKI_020). Verify checks the TSL signer
// certificate against the stored trust anchor (TUC_PKI_011) and the XML
// signature (TUC_PKI_012: exclusive canonicalization, enveloped
// signature, XAdES signed properties). CAs, OCSPResponders, IssuerService
// and AnnouncedTrustAnchor give what the trust space consists of
// (TUC_PKI_001, TUC_PKI_003, TUC_PKI_005, TUC_PKI_013), and Status returns
// the TSL-dependent part of TUC_PKI_018 (CA status, certificate type,
// OCSP with package ocsp) for ti.Verifier.
//
// The package compiles with any Go release. Brainpool certificates in the
// TSL (and the signer certificate of TSL(ECC-RSA)) parse only with the
// ivory overlay; without it they are skipped as unparsable.
package tsl
