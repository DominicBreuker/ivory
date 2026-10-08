//go:build ivory

package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

// SupportsCertificate is like chi.SupportsCertificate. For a certificate
// with a Brainpool key in TLS 1.2, it also checks that the client listed
// the key's curve in supported_groups, as TLS 1.2 requires for the
// server's ECDSA certificate (RFC 8422, Section 5.1) and OpenSSL enforces
// ("wrong curve"). crypto/tls can't make that check for keys it doesn't
// know. In TLS 1.3, the signature scheme of the key's curve (RFC 8734),
// which chi.SupportsCertificate checks, is enough.
func SupportsCertificate(chi *tls.ClientHelloInfo, c *tls.Certificate) error {
	if err := chi.SupportsCertificate(c); err != nil {
		return err
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return err
		}
	}
	pub, err := x509util.PublicKey(leaf)
	if err != nil {
		return nil // not a Brainpool key
	}
	bp, ok := pub.(*brainpool.PublicKey)
	if !ok {
		return nil
	}
	// crypto/tls signs with a Brainpool key only with TLS 1.3 schemes in
	// TLS 1.3, and only with TLS 1.2 schemes in TLS 1.2, so a copy of c
	// with only its TLS 1.3 scheme fits exactly when TLS 1.3 is used.
	tls13 := *c
	tls13.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls13SchemeForCurve(bp.Curve())}
	if chi.SupportsCertificate(&tls13) == nil {
		return nil
	}
	id, _ := curveIDs(bp.Curve())
	if !slices.Contains(chi.SupportedCurves, id) {
		return fmt.Errorf("tlsutil: client doesn't support the certificate's curve %v", bp.Curve())
	}
	return nil
}

// GetCertificate returns a tls.Config.GetCertificate function that picks
// the first of certs that SupportsCertificate accepts. If none fits, it
// returns the first, as crypto/tls does.
func GetCertificate(certs []tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(certs) == 0 {
			return nil, fmt.Errorf("tlsutil: no certificates")
		}
		for i := range certs {
			if SupportsCertificate(chi, &certs[i]) == nil {
				return &certs[i], nil
			}
		}
		return &certs[0], nil
	}
}
