package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
)

// A ChainVerifier checks a peer's certificate chain whose keys
// x509.Certificate.Verify doesn't support. Use its VerifyConnection method
// as tls.Config.VerifyConnection, with InsecureSkipVerify set in clients
// and ClientAuth set to RequireAnyClientCert in servers.
//
// It checks that each certificate is signed by the next one in the chain,
// until one is signed by a root; that all of them, the root included, are
// valid at the current time; that the issuers are CAs and their path
// length constraints hold; that no certificate of the chain has a critical
// extension crypto/x509 doesn't process (RFC 5280, Section 4.2); and that
// the leaf allows KeyUsage. It does no path building and checks no name
// constraints, policies or revocation.
type ChainVerifier struct {
	// Roots are the trusted CA certificates.
	Roots []*x509.Certificate

	// KeyUsage is the extended key usage the leaf must allow, if it has
	// the extension. With x509.ExtKeyUsageServerAuth, VerifyConnection
	// also checks the leaf against ConnectionState.ServerName.
	KeyUsage x509.ExtKeyUsage

	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time
}

// VerifyConnection verifies cs.PeerCertificates. It fails if there are
// none.
func (v *ChainVerifier) VerifyConnection(cs tls.ConnectionState) error {
	var name string
	if v.KeyUsage == x509.ExtKeyUsageServerAuth {
		name = cs.ServerName
	}
	return v.Verify(cs.PeerCertificates, name)
}

// Verify verifies chain, which starts with the leaf. If dnsName is not
// empty, the leaf must be valid for it.
func (v *ChainVerifier) Verify(chain []*x509.Certificate, dnsName string) error {
	if len(chain) == 0 {
		return errors.New("tlsutil: no peer certificate")
	}
	now := time.Now()
	if v.Time != nil {
		now = v.Time()
	}
	leaf := chain[0]
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, v.KeyUsage) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return fmt.Errorf("tlsutil: certificate %q doesn't allow extended key usage %v", leaf.Subject, v.KeyUsage)
	}
	if dnsName != "" {
		if err := leaf.VerifyHostname(dnsName); err != nil {
			return err
		}
	}
	for i, c := range chain {
		if err := checkValidity(c, now); err != nil {
			return err
		}
		if slices.ContainsFunc(v.Roots, func(root *x509.Certificate) bool { return bytes.Equal(c.Raw, root.Raw) }) {
			return nil
		}
		if len(c.UnhandledCriticalExtensions) > 0 {
			return fmt.Errorf("tlsutil: certificate %q has an unhandled critical extension %v", c.Subject, c.UnhandledCriticalExtensions[0])
		}
		if i > 0 {
			// c is an intermediate with i-1 intermediates below it.
			if err := checkPathLen(c, i-1); err != nil {
				return err
			}
		}
		for _, root := range v.Roots {
			if bytes.Equal(c.RawIssuer, root.RawSubject) && x509util.CheckCertificateSignatureFrom(c, root) == nil {
				if err := checkPathLen(root, i); err != nil {
					return err
				}
				return checkValidity(root, now)
			}
		}
		if i+1 == len(chain) {
			break
		}
		next := chain[i+1]
		if !bytes.Equal(c.RawIssuer, next.RawSubject) {
			return fmt.Errorf("tlsutil: certificate %q is not issued by the next certificate in the chain", c.Subject)
		}
		if err := x509util.CheckCertificateSignatureFrom(c, next); err != nil {
			return fmt.Errorf("tlsutil: certificate %q: bad signature by %q: %w", c.Subject, next.Subject, err)
		}
	}
	return fmt.Errorf("tlsutil: certificate %q is not signed by a trusted root", chain[len(chain)-1].Subject)
}

// checkPathLen checks ca's path length constraint for a path with n
// intermediate certificates below ca.
func checkPathLen(ca *x509.Certificate, n int) error {
	if ca.BasicConstraintsValid && ca.MaxPathLen >= 0 && n > ca.MaxPathLen {
		return fmt.Errorf("tlsutil: certificate %q allows a path length of %d, the chain has %d intermediates below it", ca.Subject, ca.MaxPathLen, n)
	}
	return nil
}

func checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("tlsutil: certificate %q is not valid at %v (valid from %v to %v)",
			c.Subject, now.UTC().Format(time.RFC3339), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
