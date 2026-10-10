package ocsp

import (
	"bytes"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// DefaultTolerance is the time tolerance for producedAt, thisUpdate and
// nextUpdate of GS-A_5215 (gemSpec_PKI V2.28.0): "Produkttypen der TI,
// die Zertifikate prüfen, MÜSSEN die Toleranz ‚t‘ auf genau 37,5 Sekunden
// ansetzen."
const DefaultTolerance = 37500 * time.Millisecond

// Errors of Verify and Checker. They are named after the error codes of
// TUC_PKI_006 (gemSpec_PKI V2.28.0, GS-A_4657-03); the errors returned
// wrap them, so test with errors.Is.
var (
	// ErrNotAvailable: the responder could not be reached or didn't
	// answer in time (OCSP_NOT_AVAILABLE, step 4c).
	ErrNotAvailable = errors.New("OCSP_NOT_AVAILABLE")
	// ErrCertMissing: no trusted OCSP signer certificate matches the
	// responder of the response (OCSP_CERT_MISSING, step 5a).
	ErrCertMissing = errors.New("OCSP_CERT_MISSING")
	// ErrSignature: the response signature is invalid
	// (OCSP_SIGNATURE_ERROR, step 5a1).
	ErrSignature = errors.New("OCSP_SIGNATURE_ERROR")
	// ErrStatus: the responseStatus is not successful (OCSP_STATUS_ERROR,
	// step 6a).
	ErrStatus = errors.New("OCSP_STATUS_ERROR")
	// ErrCheckRevocation: the response doesn't fit the request (CertID,
	// nonce), its times are outside the tolerance, or it is malformed
	// (OCSP_CHECK_REVOCATION_ERROR, steps 4b and 6b).
	ErrCheckRevocation = errors.New("OCSP_CHECK_REVOCATION_ERROR")
	// ErrCertHashMissing: the single response has no certHash extension
	// (CERTHASH_EXTENSION_MISSING, step 7b).
	ErrCertHashMissing = errors.New("CERTHASH_EXTENSION_MISSING")
	// ErrCertHashMismatch: the certHash doesn't match the certificate
	// (CERTHASH_MISMATCH, step 7c).
	ErrCertHashMismatch = errors.New("CERTHASH_MISMATCH")
	// ErrRevoked: the certificate is revoked (CERT_REVOKED, step 8b).
	ErrRevoked = errors.New("CERT_REVOKED")
	// ErrUnknown: the responder doesn't know the certificate
	// (CERT_UNKNOWN, step 8c).
	ErrUnknown = errors.New("CERT_UNKNOWN")
)

// VerifyOptions are the options of Response.Verify.
type VerifyOptions struct {
	// Issuer is the certificate of the CA that issued the certificate.
	Issuer *x509.Certificate

	// Responders are the trusted OCSP signer certificates. In the TI,
	// these are the certificates of the TSL's services with type
	// "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
	// (TUC_PKI_006 step 5). The response must be signed by one of them,
	// identified by its responder ID (byName: subject; byKey: SHA-1 hash
	// of the public key). Certificates in the response are ignored.
	Responders []*x509.Certificate

	// Time is the local time at which the response was received. If zero,
	// time.Now is used.
	Time time.Time

	// ProducedAtPast and ProducedAtFuture are the tolerances for producedAt
	// before and after Time; UpdateTolerance is the tolerance for
	// thisUpdate after Time and nextUpdate before Time. Zero means
	// DefaultTolerance (GS-A_5215).
	ProducedAtPast, ProducedAtFuture, UpdateTolerance time.Duration

	// SkipCertHash turns off the certHash check (TUC_PKI_006 parameter
	// ENFORCE_CERTHASH_CHECK = false, step 7a). By default the check is
	// on, as the specification's default.
	SkipCertHash bool

	// Nonce, if not nil, must be the value of the response's nonce
	// extension, as sent with RequestOptions.Nonce.
	Nonce []byte
}

func orDefault(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultTolerance
	}
	return d
}

// Verify checks that r is a valid, trusted OCSP response that reports
// cert as good, as TUC_PKI_006 steps 5 to 8 require (see the package
// documentation), and returns the single response about cert.
//
// A revoked certificate whose revocation time is after opts.Time counts
// as good (step 8a).
func (r *Response) Verify(cert *x509.Certificate, opts VerifyOptions) (*SingleResponse, error) {
	if cert == nil || opts.Issuer == nil {
		return nil, errors.New("ocsp: Verify needs the certificate and its issuer")
	}
	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}
	if r.Status != Successful {
		return nil, fmt.Errorf("ocsp: response status %v: %w", r.Status, ErrStatus)
	}
	if err := r.checkResponder(opts.Responders); err != nil {
		return nil, err
	}
	var sr *SingleResponse
	for i := range r.Responses {
		if r.Responses[i].CertID.Matches(cert, opts.Issuer) {
			sr = &r.Responses[i]
			break
		}
	}
	if sr == nil {
		return nil, fmt.Errorf("ocsp: no single response for certificate %q (serial %v): %w", cert.Subject, cert.SerialNumber, ErrCheckRevocation)
	}
	if n := r.Nonce(); opts.Nonce != nil && !bytes.Equal(n, octetString(opts.Nonce)) && !bytes.Equal(n, opts.Nonce) {
		return nil, fmt.Errorf("ocsp: response nonce doesn't match the request: %w", ErrCheckRevocation)
	}
	if d := orDefault(opts.ProducedAtPast); r.ProducedAt.Before(now.Add(-d)) {
		return nil, fmt.Errorf("ocsp: producedAt %v is more than %v before %v: %w", r.ProducedAt, d, now.UTC(), ErrCheckRevocation)
	}
	if d := orDefault(opts.ProducedAtFuture); r.ProducedAt.After(now.Add(d)) {
		return nil, fmt.Errorf("ocsp: producedAt %v is more than %v after %v: %w", r.ProducedAt, d, now.UTC(), ErrCheckRevocation)
	}
	d := orDefault(opts.UpdateTolerance)
	if sr.ThisUpdate.After(now.Add(d)) {
		return nil, fmt.Errorf("ocsp: thisUpdate %v is more than %v after %v: %w", sr.ThisUpdate, d, now.UTC(), ErrCheckRevocation)
	}
	if !sr.NextUpdate.IsZero() && sr.NextUpdate.Before(now.Add(-d)) {
		return nil, fmt.Errorf("ocsp: nextUpdate %v is more than %v before %v: %w", sr.NextUpdate, d, now.UTC(), ErrCheckRevocation)
	}
	switch sr.Status {
	case Good:
	case Revoked:
		if !sr.RevokedAt.After(now) {
			return nil, fmt.Errorf("ocsp: certificate %q revoked at %v: %w", cert.Subject, sr.RevokedAt, ErrRevoked)
		}
	default:
		return nil, fmt.Errorf("ocsp: certificate %q: %w", cert.Subject, ErrUnknown)
	}
	if !opts.SkipCertHash {
		if err := sr.checkCertHash(cert); err != nil {
			return nil, err
		}
	}
	return sr, nil
}

func (sr *SingleResponse) checkCertHash(cert *x509.Certificate) error {
	if sr.CertHash == nil {
		return fmt.Errorf("ocsp: no certHash for certificate %q: %w", cert.Subject, ErrCertHashMissing)
	}
	h := sr.CertHash.HashAlgorithm
	if !h.Available() {
		return fmt.Errorf("ocsp: certHash algorithm %v not available: %w", h, ErrCertHashMismatch)
	}
	hh := h.New()
	hh.Write(cert.Raw)
	if subtle.ConstantTimeCompare(hh.Sum(nil), sr.CertHash.Hash) != 1 {
		return fmt.Errorf("ocsp: certHash doesn't match certificate %q: %w", cert.Subject, ErrCertHashMismatch)
	}
	return nil
}

// checkResponder finds the trusted responder certificates that match r's
// responder ID and checks the signature with them.
func (r *Response) checkResponder(responders []*x509.Certificate) error {
	var sigErr error
	matched := false
	for _, c := range responders {
		if !r.responderIs(c) {
			continue
		}
		matched = true
		err := r.CheckSignatureFrom(c)
		if err == nil {
			return nil
		}
		sigErr = err
	}
	if !matched {
		return fmt.Errorf("ocsp: responder %s is not a trusted OCSP signer: %w", r.responderString(), ErrCertMissing)
	}
	return fmt.Errorf("ocsp: %v: %w", sigErr, ErrSignature)
}

func (r *Response) responderIs(c *x509.Certificate) bool {
	if r.ResponderName != nil {
		return bytes.Equal(r.ResponderName, c.RawSubject)
	}
	h, err := keyHash(c)
	return err == nil && bytes.Equal(h, r.ResponderKeyHash)
}

func (r *Response) responderString() string {
	if r.ResponderName != nil {
		return fmt.Sprintf("byName %x", r.ResponderName)
	}
	return fmt.Sprintf("byKey %x", r.ResponderKeyHash)
}

// keyHash returns the SHA-1 hash of the subjectPublicKey of c (RFC 6960,
// Section 4.2.1, KeyHash).
func keyHash(c *x509.Certificate) ([]byte, error) {
	spki := cryptobyte.String(c.RawSubjectPublicKeyInfo)
	var inner cryptobyte.String
	var key cryptobyte.String
	if !spki.ReadASN1(&inner, cbasn1.SEQUENCE) || !inner.SkipASN1(cbasn1.SEQUENCE) ||
		!inner.ReadASN1(&key, cbasn1.BIT_STRING) || len(key) == 0 {
		return nil, errors.New("ocsp: malformed public key")
	}
	h := sha1.Sum(key[1:])
	return h[:], nil
}
