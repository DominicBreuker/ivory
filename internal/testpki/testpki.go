// Package testpki issues certificates with any key, Brainpool keys
// included, for tests: crypto/x509 builds the structure with a
// placeholder P-256 key, then the helper splices in the real public key
// and signs again with the issuer's key.
//
// Parsing the result needs the ivory overlay when a Brainpool key is
// involved.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Default validity of issued certificates.
var (
	Start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	End   = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

// P256 returns a new NIST P-256 key.
func P256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Brainpool returns a new key on c.
func Brainpool(t testing.TB, c brainpool.Curve) *brainpool.PrivateKey {
	t.Helper()
	k, err := brainpool.GenerateKey(c)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// SPKI returns the DER SubjectPublicKeyInfo of k's public key.
func SPKI(t testing.TB, k crypto.Signer) []byte {
	t.Helper()
	var der []byte
	var err error
	if bk, ok := k.(*brainpool.PrivateKey); ok {
		der, err = x509util.MarshalPKIXPublicKey(bk.PublicKey())
	} else {
		der, err = x509.MarshalPKIXPublicKey(k.Public())
	}
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Resign replaces field spkiField of the TBS part of the signed structure
// der (if spki is not nil) and signs it again with signer, with ECDSA and
// SHA-256.
func Resign(t testing.TB, der []byte, spkiField int, spki []byte, signer crypto.Signer) []byte {
	t.Helper()
	in := cryptobyte.String(der)
	var outer, tbs, alg cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!outer.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		t.Fatal("malformed signed structure")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := 0; !tbs.Empty(); i++ {
			var field cryptobyte.String
			if !tbs.ReadAnyASN1Element(&field, nil) {
				t.Fatal("malformed TBS")
			}
			if spki != nil && i == spkiField {
				field = spki
			}
			b.AddBytes(field)
		}
	})
	newTBS := b.BytesOrPanic()
	digest := sha256.Sum256(newTBS)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	b = cryptobyte.Builder{}
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddBytes(alg)
		b.AddASN1BitString(sig)
	})
	return b.BytesOrPanic()
}

var serial atomic.Int64

func init() { serial.Store(1000) }

// Issue returns a certificate for key, made from tmpl, issued by parent
// (self-signed if nil) and signed by parentKey with ECDSA and SHA-256.
// parentKey must be an ECDSA or Brainpool key. A zero validity becomes
// Start to End.
func Issue(t testing.TB, tmpl *x509.Certificate, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(serial.Add(1))
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = Start, End
	}
	issuer := tmpl
	if parent != nil {
		issuer = &x509.Certificate{RawSubject: parent.RawSubject, SubjectKeyId: parent.SubjectKeyId}
	}
	placeholder := P256(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, placeholder.Public(), placeholder)
	if err != nil {
		t.Fatal(err)
	}
	// The TBSCertificate: version, serial, signature, issuer, validity,
	// subject, subjectPublicKeyInfo, ...
	der = Resign(t, der, 6, SPKI(t, key), parentKey)
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// CA returns a template for a CA certificate.
func CA(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"ivory test"}},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// EE returns a template for an end-entity certificate.
func EE(cn string, ku x509.KeyUsage, eku ...x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"ivory test"}},
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
}
