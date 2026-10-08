//go:build ivory

package ti

// Test helpers that issue certificates and CRLs with any key, Brainpool
// keys included: crypto/x509 builds the structure with a placeholder P-256
// key, then the test splices in the real public key and signs again.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	testNow   = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	testStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	testEnd   = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

func testTime() time.Time { return testNow }

func newP256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newBrainpool(t testing.TB, c brainpool.Curve) *brainpool.PrivateKey {
	t.Helper()
	k, err := brainpool.GenerateKey(c)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func spkiOf(t testing.TB, k crypto.Signer) []byte {
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

// resign replaces field spkiField of the TBS part of der (if spki is not
// nil) and signs it again with signer, with ECDSA and SHA-256.
func resign(t testing.TB, der []byte, spkiField int, spki []byte, signer crypto.Signer) []byte {
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

var serial int64 = 100

// issue returns a certificate for key, made from tmpl, issued by parent
// (self-signed if nil) and signed by parentKey.
func issue(t testing.TB, tmpl *x509.Certificate, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = testStart, testEnd
	}
	issuer := tmpl
	if parent != nil {
		issuer = &x509.Certificate{RawSubject: parent.RawSubject, SubjectKeyId: parent.SubjectKeyId}
	}
	placeholder := newP256(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, placeholder.Public(), placeholder)
	if err != nil {
		t.Fatal(err)
	}
	// The TBSCertificate: version, serial, signature, issuer, validity,
	// subject, subjectPublicKeyInfo, ...
	der = resign(t, der, 6, spkiOf(t, key), parentKey)
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func eeTemplate(cn string, eku x509.ExtKeyUsage, policy x509.OID) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		Policies:              []x509.OID{policy},
		BasicConstraintsValid: true,
	}
}

// makeCRL returns a CRL issued by signer (with key signerKey) that revokes
// the given serial numbers.
func makeCRL(t testing.TB, signer *x509.Certificate, signerKey crypto.Signer, thisUpdate, nextUpdate time.Time, revoked ...*big.Int) *x509.RevocationList {
	t.Helper()
	placeholder := newP256(t)
	issuer := &x509.Certificate{
		RawSubject:   signer.RawSubject,
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCRLSign,
		PublicKey:    placeholder.Public(),
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, placeholder)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(resign(t, der, -1, nil, signerKey))
	if err != nil {
		t.Fatal(err)
	}
	return crl
}
