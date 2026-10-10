package tsl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/DominicBreuker/ivory/ocsp"
)

// Errors of the status check, named after the error codes of gemSpec_PKI
// V2.28.0.
var (
	// ErrCARevoked: the CA's service is revoked in the TSL and the
	// certificate was issued after the revocation
	// (CA_CERTIFICATE_REVOKED_IN_TSL, TUC_PKI_018 step 5a).
	ErrCARevoked = errors.New("CA_CERTIFICATE_REVOKED_IN_TSL")
	// ErrCertTypeNotAuthorized: the CA may not issue the certificate's
	// type (CERT_TYPE_CA_NOT_AUTHORIZED, TUC_PKI_007 step 9a).
	ErrCertTypeNotAuthorized = errors.New("CERT_TYPE_CA_NOT_AUTHORIZED")
)

// StatusOptions are the options of Status.
type StatusOptions struct {
	// Policies is the PolicyList of TUC_PKI_007: the certificate type
	// OIDs the caller accepts. The certificate's type among them must be
	// one the CA may issue: one of the ExtensionOIDs of its service
	// (TUC_PKI_007 step 8). If empty, every certificate policy of the
	// certificate counts.
	Policies []x509.OID

	// OCSP asks the CA's OCSP responder (TUC_PKI_018 step 7), at the
	// address of the CA's ServiceSupplyPoint (TUC_PKI_005), with the
	// OCSP signer certificates of the TSL. If nil, no status is asked
	// (offline mode, step 6).
	OCSP *ocsp.Checker

	// TolerateOCSPFailure accepts the certificate when the responder
	// can't be reached (TUC_PKI_006 TOLERATE_OCSP_FAILURE = true, step
	// 4a); OnWarning, if set, receives the error.
	TolerateOCSPFailure bool
	OnWarning           func(error)

	// Context is used for OCSP requests. If nil, context.Background.
	Context context.Context
}

// Status returns a function that checks what TUC_PKI_018 needs from the
// TSL for a certificate cert, issued by the CA certificate ca, after its
// signature, validity and key usages have been checked (for example by
// ti.Verifier, whose Status field takes the function):
//
//   - ca is a CA of the TSL; if its service is revoked, cert's notBefore
//     must lie before the service's StatusStartingTime (step 5);
//   - the CA may issue cert's certificate type (TUC_PKI_007 step 8);
//   - the OCSP responder of the CA reports cert as good (step 7).
//
// The function keeps t; to change the trust space, build a new function
// from the new TSL.
func (t *TSL) Status(opts StatusOptions) func(cert, ca *x509.Certificate) error {
	return func(cert, ca *x509.Certificate) error {
		s := t.ServiceOf(TypeCA, ca)
		if s == nil {
			return fmt.Errorf("tsl: CA %q is not in the TSL: %w", ca.Subject, ErrCAMissing)
		}
		if s.Status == StatusRevoked && !cert.NotBefore.Before(s.StatusStart) {
			return fmt.Errorf("tsl: certificate %q issued after its CA was revoked at %v: %w", cert.Subject, s.StatusStart, ErrCARevoked)
		}
		if s.Status != StatusInAccord && s.Status != StatusRevoked {
			return fmt.Errorf("tsl: CA %q has status %q: %w", ca.Subject, s.Status, ErrCAMissing)
		}
		if !authorized(cert, s, opts.Policies) {
			return fmt.Errorf("tsl: CA %q may not issue the type of certificate %q: %w", ca.Subject, cert.Subject, ErrCertTypeNotAuthorized)
		}
		if opts.OCSP == nil {
			return nil
		}
		ctx := opts.Context
		if ctx == nil {
			ctx = context.Background()
		}
		_, _, err := opts.OCSP.Check(ctx, cert, ca, s.OCSPLocation(), t.OCSPResponders())
		if err != nil && opts.TolerateOCSPFailure && errors.Is(err, ocsp.ErrNotAvailable) {
			if opts.OnWarning != nil {
				opts.OnWarning(err)
			}
			return nil
		}
		return err
	}
}

func authorized(cert *x509.Certificate, s *Service, policies []x509.OID) bool {
	for _, p := range cert.Policies {
		if len(policies) > 0 && !slices.ContainsFunc(policies, p.Equal) {
			continue
		}
		if s.HasExtensionOID(p.String()) {
			return true
		}
	}
	return false
}
