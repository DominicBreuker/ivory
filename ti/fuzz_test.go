//go:build ivory

package ti

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
)

// FuzzVerifierCRL feeds CRLs to a Verifier that requires one: Verify must
// never panic, and it may accept the certificate only if the CRL is signed
// by the CA, current, and doesn't list the certificate. The CA and the
// certificate are the fixed ones of testdata/pki, so that a failing input
// stays valid.
func FuzzVerifierCRL(f *testing.F) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../testdata/pki/" + name)
		if err != nil {
			f.Fatal(err)
		}
		block, _ := pem.Decode(b)
		return block.Bytes
	}
	ca, err := x509.ParseCertificate(read("bp256-ca.pem"))
	if err != nil {
		f.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(read("bp256-client.pem"))
	if err != nil {
		f.Fatal(err)
	}
	k, err := x509util.ParsePKCS8PrivateKey(read("bp256-ca.key"))
	if err != nil {
		f.Fatal(err)
	}
	caKey := k.(crypto.Signer)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, revoked := range [][]*big.Int{nil, {big.NewInt(7)}, {leaf.SerialNumber}} {
		f.Add(makeCRL(f, ca, caKey, now.Add(-time.Hour), now.Add(time.Hour), revoked...).Raw)
	}
	// The first seeds must reach the accepting path.
	good := makeCRL(f, ca, caKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err := (&Verifier{CAs: []*x509.Certificate{ca}, CRLs: []CRL{{List: good, CA: ca}}, RequireCRL: true, Time: func() time.Time { return now }}).Verify(leaf, ""); err != nil {
		f.Fatalf("seed CRL rejected: %v", err)
	}
	f.Add(makeCRL(f, ca, caKey, now.Add(-2*time.Hour), now.Add(-time.Hour)).Raw)

	f.Fuzz(func(t *testing.T, der []byte) {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return
		}
		v := &Verifier{CAs: []*x509.Certificate{ca}, CRLs: []CRL{{List: crl, CA: ca}}, RequireCRL: true, Time: func() time.Time { return now }}
		if v.Verify(leaf, "") != nil {
			return
		}
		if err := x509util.CheckCRLSignatureFrom(crl, ca); err != nil {
			t.Fatalf("accepted a CRL with a bad signature: %v", err)
		}
		if now.Before(crl.ThisUpdate) || !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
			t.Fatalf("accepted a CRL that isn't current: %v to %v", crl.ThisUpdate, crl.NextUpdate)
		}
		if slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(leaf.SerialNumber) == 0 }) {
			t.Fatal("accepted a revoked certificate")
		}
	})
}
