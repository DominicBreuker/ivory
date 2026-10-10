package tsl

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/DominicBreuker/ivory/internal/xmldsig"
	"slices"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
)

// Errors of Verify and AnnouncedTrustAnchor, named after the error codes
// of gemSpec_PKI V2.28.0; the errors returned wrap them.
var (
	// ErrSignature: the XML signature is invalid or has a form this
	// package doesn't support (XML_SIGNATURE_ERROR, TUC_PKI_012).
	ErrSignature = xmldsig.ErrSignature
	// ErrCertExtraction: the TSL signer certificate can't be extracted
	// (TSL_CERT_EXTRACTION_ERROR, TUC_PKI_011), or an announced trust
	// anchor can't (TSL_SIG_CERT_EXTRACTION_ERROR, TUC_PKI_013).
	ErrCertExtraction = errors.New("TSL_CERT_EXTRACTION_ERROR")
	// ErrKeyUsage: the TSL signer certificate lacks nonRepudiation
	// (WRONG_KEYUSAGE).
	ErrKeyUsage = errors.New("WRONG_KEYUSAGE")
	// ErrExtKeyUsage: the TSL signer certificate lacks id-tsl-kp-tslSigning
	// (WRONG_EXTENDEDKEYUSAGE).
	ErrExtKeyUsage = errors.New("WRONG_EXTENDEDKEYUSAGE")
	// ErrCertValidity: a certificate is not valid at the time of the check
	// (TUC_PKI_002: CERTIFICATE_NOT_VALID_TIME).
	ErrCertValidity = errors.New("CERTIFICATE_NOT_VALID_TIME")
	// ErrCertSignature: the TSL signer certificate is not signed by a
	// trust anchor (TUC_PKI_004: CERT_SIGNATURE_ERROR).
	ErrCertSignature = errors.New("CERT_SIGNATURE_ERROR")
	// ErrMultipleTrustAnchors: more than one announced trust anchor
	// (MULTIPLE_TRUST_ANCHOR, TUC_PKI_013).
	ErrMultipleTrustAnchors = errors.New("MULTIPLE_TRUST_ANCHOR")
)

// OIDTSLSigning is id-tsl-kp-tslSigning (ETSI TS 102 231, Section 6.2),
// the extended key usage of TSL signer certificates.
var OIDTSLSigning = asn1.ObjectIdentifier{0, 4, 0, 2231, 3, 0}

// VerifyOptions are the options of Verify.
type VerifyOptions struct {
	// TrustAnchors are the TSL signer CA certificates (the TI trust
	// anchor, for example GEM.TSL-CA51), stored securely by the system
	// (TUC_PKI_011 step 4). They may have Brainpool keys.
	TrustAnchors []*x509.Certificate

	// Time is the time of the check. If zero, time.Now is used.
	Time time.Time
}

// Verify checks the TSL's signer certificate (TUC_PKI_011: validity, key
// usage nonRepudiation, extended key usage id-tsl-kp-tslSigning, signature
// by a trust anchor) and its XML signature (TUC_PKI_012), and returns the
// signer certificate. The OCSP check of the signer certificate
// (TUC_PKI_001 step 4) is the caller's: it must use the responders and
// addresses of the TSL already in the system, never those of the TSL
// being checked.
//
// Verify doesn't check NextUpdate; see Expired.
func (t *TSL) Verify(opts VerifyOptions) (*x509.Certificate, error) {
	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}
	sig, err := xmldsig.FindSignature(t.doc)
	if err != nil {
		return nil, err
	}
	if len(sig.Certs) != 1 {
		return nil, fmt.Errorf("tsl: signature has %d signer certificates: %w", len(sig.Certs), ErrCertExtraction)
	}
	signer, err := x509.ParseCertificate(sig.Certs[0])
	if err != nil {
		return nil, fmt.Errorf("tsl: signer certificate: %v: %w", err, ErrCertExtraction)
	}
	if err := CheckValidity(signer, now); err != nil {
		return nil, err
	}
	if signer.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return nil, fmt.Errorf("tsl: signer certificate %q lacks key usage nonRepudiation: %w", signer.Subject, ErrKeyUsage)
	}
	if !slices.ContainsFunc(signer.UnknownExtKeyUsage, OIDTSLSigning.Equal) {
		return nil, fmt.Errorf("tsl: signer certificate %q lacks extended key usage tslSigning: %w", signer.Subject, ErrExtKeyUsage)
	}
	var anchorErr error = fmt.Errorf("tsl: no trust anchor issued the signer certificate %q: %w", signer.Subject, ErrCertSignature)
	trusted := false
	for _, a := range opts.TrustAnchors {
		if string(a.RawSubject) != string(signer.RawIssuer) {
			continue
		}
		if err := x509util.CheckCertificateSignatureFrom(signer, a); err != nil {
			anchorErr = fmt.Errorf("tsl: signer certificate %q: %v: %w", signer.Subject, err, ErrCertSignature)
			continue
		}
		trusted = true
		break
	}
	if !trusted {
		return nil, anchorErr
	}
	if err := sig.VerifyReferences(t.doc); err != nil {
		return nil, err
	}
	if err := sig.VerifyValue(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

// SignerCertificate returns the TSL signer certificate from the signature,
// without checking anything. It is the certificate whose status the
// caller asks the OCSP responder about (TUC_PKI_001 step 3).
func (t *TSL) SignerCertificate() (*x509.Certificate, error) {
	sig, err := xmldsig.FindSignature(t.doc)
	if err != nil {
		return nil, err
	}
	if len(sig.Certs) != 1 {
		return nil, fmt.Errorf("tsl: signature has %d signer certificates: %w", len(sig.Certs), ErrCertExtraction)
	}
	c, err := x509.ParseCertificate(sig.Certs[0])
	if err != nil {
		return nil, fmt.Errorf("tsl: signer certificate: %v: %w", err, ErrCertExtraction)
	}
	return c, nil
}

// CheckValidity checks that c is valid at now (TUC_PKI_002).
func CheckValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("tsl: certificate %q is not valid at %v (valid from %v to %v): %w",
			c.Subject, now.UTC().Format(time.RFC3339), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), ErrCertValidity)
	}
	return nil
}

// Expired reports whether the TSL's NextUpdate plus grace lies before now
// (TUC_PKI_019 and GS-A_5336: a TSL past its NextUpdate and grace period
// must not be used). A TSL without NextUpdate never expires.
func (t *TSL) Expired(now time.Time, grace time.Duration) bool {
	return !t.NextUpdate.IsZero() && now.After(t.NextUpdate.Add(grace))
}

// AnnouncedTrustAnchor returns the new TI trust anchor that the TSL
// announces (TUC_PKI_013): the CA certificate of the service with type
// TSLServiceCertChange, and its StatusStartingTime, before which it must
// not be activated. It returns nil and no error if the TSL announces none.
// The certificate must be valid at its StatusStartingTime (step 4).
func (t *TSL) AnnouncedTrustAnchor() (*x509.Certificate, time.Time, error) {
	svcs := t.ServicesOfType(TypeTSLServiceCertChg)
	switch len(svcs) {
	case 0:
		return nil, time.Time{}, nil
	case 1:
	default:
		return nil, time.Time{}, fmt.Errorf("tsl: %d announced trust anchors: %w", len(svcs), ErrMultipleTrustAnchors)
	}
	s := svcs[0]
	if len(s.Certificates) != 1 || len(s.certs) != 1 {
		return nil, time.Time{}, fmt.Errorf("tsl: announced trust anchor can't be extracted: %w", ErrCertExtraction)
	}
	c := s.certs[0]
	if err := CheckValidity(c, s.StatusStart); err != nil {
		return nil, time.Time{}, err
	}
	return c, s.StatusStart, nil
}
