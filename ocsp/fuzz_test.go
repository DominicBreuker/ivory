package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/DominicBreuker/ivory/internal/testpki"
)

// FuzzParseResponse parses arbitrary responses and verifies them against
// a fixed responder: nothing may panic, and Verify may succeed only if
// the response is signed by the responder.
func FuzzParseResponse(f *testing.F) {
	// A fixed fixture, so that failing inputs stay meaningful.
	key := func(d int64) *ecdsa.PrivateKey {
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), big.NewInt(d).FillBytes(make([]byte, 32)))
		if err != nil {
			f.Fatal(err)
		}
		return k
	}
	caKey, responderKey := key(1001), key(1002)
	fx := &fixture{caKey: caKey, responderKey: responderKey}
	tmpl := testpki.CA("Fuzz CA")
	tmpl.SerialNumber = big.NewInt(1)
	fx.ca = testpki.Issue(f, tmpl, caKey, nil, caKey)
	leaf := testpki.EE("leaf", x509.KeyUsageDigitalSignature)
	leaf.SerialNumber = big.NewInt(2)
	fx.leaf = testpki.Issue(f, leaf, key(1003), fx.ca, caKey)
	resp := testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageOCSPSigning)
	resp.SerialNumber = big.NewInt(3)
	fx.responder = testpki.Issue(f, resp, responderKey, fx.ca, caKey)

	good := fx.good(f)
	f.Add(fx.create(f, good))
	good.ResponderByName = true
	good.Responses[0].Status = Revoked
	f.Add(fx.create(f, good))
	f.Add([]byte{0x30, 0x03, 0x0a, 0x01, 0x03})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseResponse(data)
		if err != nil {
			return
		}
		opts := fx.opts()
		opts.Time = r.ProducedAt
		if _, err := r.Verify(fx.leaf, opts); err == nil {
			if r.CheckSignatureFrom(fx.responder) != nil {
				t.Fatal("Verify accepted a response not signed by the responder")
			}
		}
	})
}
