//go:build ivory

package tlsutil

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

// FuzzVerifyUnsupportedSignature checks that VerifyUnsupportedSignature
// never panics on any peer key, scheme, message and signature, and that it
// accepts a signature only for a Brainpool key, with a scheme allowed for
// that key, when brainpool.VerifyASN1 accepts it too.
func FuzzVerifyUnsupportedSignature(f *testing.F) {
	for _, c := range []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()} {
		k, err := brainpool.GenerateKey(c)
		if err != nil {
			f.Fatal(err)
		}
		spki, err := x509util.MarshalPKIXPublicKey(k.PublicKey())
		if err != nil {
			f.Fatal(err)
		}
		for _, s := range []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512, tls13SchemeForCurve(c)} {
			h, _ := schemeHash(s)
			msg := []byte("signed handshake data")
			hh := h.New()
			hh.Write(msg)
			sig, err := k.Sign(rand.Reader, hh.Sum(nil), h)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(spki, uint16(s), msg, sig)
		}
	}
	f.Fuzz(func(t *testing.T, spki []byte, scheme uint16, signed, sig []byte) {
		s := tls.SignatureScheme(scheme)
		err := VerifyUnsupportedSignature(&x509.Certificate{RawSubjectPublicKeyInfo: spki}, s, signed, sig)
		if err != nil {
			return
		}
		k, perr := x509util.ParsePKIXPublicKey(spki)
		pub, ok := k.(*brainpool.PublicKey)
		if perr != nil || !ok {
			t.Fatalf("accepted a signature by a %T key (%v)", k, perr)
		}
		h, curve := schemeHash(s)
		if h == 0 || curve != nil && curve != pub.Curve() {
			t.Fatalf("accepted scheme %v for a key on %v", s, pub.Curve())
		}
		hh := h.New()
		hh.Write(signed)
		if !brainpool.VerifyASN1(pub, hh.Sum(nil), sig) {
			t.Fatal("accepted a signature that brainpool.VerifyASN1 rejects")
		}
	})
}

// schemeHash returns the hash of a scheme allowed for Brainpool keys, and
// the curve the scheme is bound to (nil for the TLS 1.2 schemes, which
// aren't bound to a curve), or zero.
func schemeHash(s tls.SignatureScheme) (crypto.Hash, brainpool.Curve) {
	switch s {
	case tls.ECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case tls.ECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case tls.ECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	case ECDSABrainpoolP256r1TLS13SHA256:
		return crypto.SHA256, brainpool.P256r1()
	case ECDSABrainpoolP384r1TLS13SHA384:
		return crypto.SHA384, brainpool.P384r1()
	case ECDSABrainpoolP512r1TLS13SHA512:
		return crypto.SHA512, brainpool.P512r1()
	}
	return 0, nil
}
