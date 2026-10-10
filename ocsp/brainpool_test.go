//go:build ivory

package ocsp

import (
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/internal/testpki"
	xocsp "golang.org/x/crypto/ocsp"
)

// TestBrainpoolResponders: responses signed with Brainpool keys, about
// certificates of a Brainpool CA, as the TI's OCSP responders send them
// (75 of the 115 OCSP signers of the production TSL use brainpoolP256r1).
func TestBrainpoolResponders(t *testing.T) {
	for _, c := range []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()} {
		t.Run(c.String(), func(t *testing.T) {
			f := newFixture(t, testpki.Brainpool(t, brainpool.P256r1()), testpki.Brainpool(t, c))
			for _, byName := range []bool{false, true} {
				tmpl := f.good(t)
				tmpl.ResponderByName = byName
				der := f.create(t, tmpl)
				sr, err := verify(t, der, f.leaf, f.opts())
				if err != nil || sr.Status != Good {
					t.Fatalf("byName=%v: %v", byName, err)
				}
				r, _ := ParseResponse(der)
				if len(r.Certificates) != 1 {
					t.Fatal("embedded certificate missing")
				}
			}
		})
	}
}

// TestXCryptoFailsOnBrainpool documents why this package exists:
// golang.org/x/crypto/ocsp rejects a response that embeds a Brainpool
// signer certificate, even without an issuer to check against.
func TestXCryptoFailsOnBrainpool(t *testing.T) {
	f := newFixture(t, testpki.Brainpool(t, brainpool.P256r1()), testpki.Brainpool(t, brainpool.P256r1()))
	der := f.create(t, f.good(t))
	if _, err := xocsp.ParseResponse(der, nil); err == nil {
		t.Error("x/crypto/ocsp parsed a response with an embedded Brainpool certificate; update the package documentation")
	}
	if _, err := verify(t, der, f.leaf, f.opts()); err != nil {
		t.Error(err)
	}
}

// TestBrainpoolMixed: an RSA CA's certificate with a Brainpool responder
// (A_23142-01 allows ECC responders for RSA certificates) and a Brainpool
// CA's certificate with a P-256 responder.
func TestBrainpoolMixed(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.Brainpool(t, brainpool.P256r1()))
	if _, err := verify(t, f.create(t, f.good(t)), f.leaf, f.opts()); err != nil {
		t.Error(err)
	}
	f = newFixture(t, testpki.Brainpool(t, brainpool.P256r1()), testpki.P256(t))
	if _, err := verify(t, f.create(t, f.good(t)), f.leaf, f.opts()); err != nil {
		t.Error(err)
	}
}

func TestBrainpoolWrongKey(t *testing.T) {
	f := newFixture(t, testpki.Brainpool(t, brainpool.P256r1()), testpki.Brainpool(t, brainpool.P256r1()))
	tmpl := f.good(t)
	tmpl.ResponderByName = true
	der, err := CreateResponse(tmpl, f.responder, testpki.Brainpool(t, brainpool.P256r1()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, der, f.leaf, f.opts()); !errors.Is(err, ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
	// byKey with another key: the responder isn't found at all.
	tmpl.ResponderByName = false
	impostor := testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature), testpki.Brainpool(t, brainpool.P256r1()), f.ca, f.caKey)
	der, err = CreateResponse(tmpl, impostor, crypto.Signer(testpki.Brainpool(t, brainpool.P256r1())))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t, der, f.leaf, f.opts()); !errors.Is(err, ErrCertMissing) {
		t.Errorf("got %v, want ErrCertMissing", err)
	}
}
