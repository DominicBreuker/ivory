//go:build ivory

package x509util

// Tests that need a crypto/x509 that parses certificates with Brainpool
// keys (patch P1 of the ivory overlay).

import (
	"crypto/x509"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
)

func parsePEMCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(readPEM(t, name+".pem").Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// TestOpenSSLChains checks the OpenSSL-made test PKI: every certificate
// against its issuer, the CAs' self-signatures, and the negative cases.
func TestOpenSSLChains(t *testing.T) {
	for _, tt := range []struct {
		child, parent string
		ok            bool
	}{
		{"bp256-ca", "bp256-ca", true},
		{"bp384-ca", "bp384-ca", true},
		{"bp512-ca", "bp512-ca", true},
		{"bp256-server", "bp256-ca", true},
		{"bp256-client", "bp256-ca", true},
		{"bp384-server", "bp384-ca", true},
		{"bp384-client", "bp384-ca", true},
		{"bp512-server", "bp512-ca", true},
		{"bp512-client", "bp512-ca", true},
		{"p256-under-bp256", "bp256-ca", true},
		{"bp256-under-p256", "p256-ca", true},
		{"bp256-server", "bp256-evil-ca", false},
		{"bp256-server", "bp384-ca", false},
		{"bp256-ca", "bp256-server", false}, // not a CA
	} {
		t.Run(tt.child+" by "+tt.parent, func(t *testing.T) {
			err := CheckCertificateSignatureFrom(parsePEMCert(t, tt.child), parsePEMCert(t, tt.parent))
			if tt.ok != (err == nil) {
				t.Errorf("err = %v, want ok = %v", err, tt.ok)
			}
		})
	}
}

// TestPublicKeyFromCertificate checks that PublicKey returns the key of
// a parsed Brainpool certificate, whose PublicKey field is nil.
func TestPublicKeyFromCertificate(t *testing.T) {
	for _, tt := range brainpoolKeys {
		c := parsePEMCert(t, tt.name)
		if c.PublicKey != nil || c.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			t.Errorf("%s: crypto/x509 returned key %T, algorithm %v", tt.name, c.PublicKey, c.PublicKeyAlgorithm)
		}
		pub, err := PublicKey(c)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ParsePKCS8PrivateKey(readPEM(t, tt.name+".key").Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !k.(*brainpool.PrivateKey).PublicKey().Equal(pub) {
			t.Errorf("%s: PublicKey doesn't match the private key", tt.name)
		}
	}
}

// TestGeneratedCertificatesParse checks that the test helper's
// certificates parse with the overlay, so parseCert doesn't synthesize
// them in this build.
func TestGeneratedCertificatesParse(t *testing.T) {
	kp := newBrainpoolPair(t, brainpool.P512r1())
	tmpl := certTemplate{issuer: "x", subject: "x", spki: kp.spki, isCA: boolPtr(false), keyUsage: x509.KeyUsageCRLSign}
	c, err := x509.ParseCertificate(makeCert(t, tmpl, kp.signer))
	if err != nil {
		t.Fatal(err)
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageCRLSign || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("parsed IsCA %v, BasicConstraintsValid %v, KeyUsage %v, SignatureAlgorithm %v",
			c.IsCA, c.BasicConstraintsValid, c.KeyUsage, c.SignatureAlgorithm)
	}
}
