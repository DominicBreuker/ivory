// Package ocsp creates OCSP requests and parses and verifies OCSP
// responses (RFC 6960) whose responders may sign with Brainpool keys, as
// the OCSP responders of the German health care telematics infrastructure
// (TI) do.
//
// golang.org/x/crypto/ocsp can't be used for such responses: it checks
// the signature with crypto/x509, which has no Brainpool support, and it
// rejects every response that embeds a Brainpool signer certificate even
// when no issuer is given. This package parses responses itself and
// checks signatures with package x509util.
//
// Verify implements the response checks of TUC_PKI_006 (gemSpec_PKI
// V2.28.0, GS-A_4657-03, steps 5 to 8): the signer must be one of the
// OCSP signer certificates the caller trusts (in the TI, those of the TSL
// with service type ".../Svctype/Certstatus/OCSP"), the response status
// must be successful, the CertID must match the certificate, producedAt,
// thisUpdate and nextUpdate must lie within the tolerance of GS-A_5215
// (37.5 seconds), the certHash extension (1.3.36.8.3.13) must match the
// certificate, and the certificate status must be good. The errors wrap
// sentinel values named after the error codes of gemSpec_PKI, so that
// callers can log them as TUC_PKI_006 does.
//
// Checker sends requests over HTTP (POST, RFC 6960 Appendix A.1), keeps
// verified responses for a grace period, and verifies the responses it
// receives; Responder-side code (test responders, simulators) can use
// ParseRequest and CreateResponse.
//
// The package compiles with any Go release. Parsing a certificate with a
// Brainpool key into an *x509.Certificate needs the ivory overlay (see
// package x509util), so callers that verify Brainpool-signed responses
// build with it.
package ocsp
