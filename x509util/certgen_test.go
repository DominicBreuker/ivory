package x509util

// Test helpers that build certificates and CRLs with cryptobyte and sign
// them with any crypto.Signer, Brainpool keys included.

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var sigAlgOIDs = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.ECDSAWithSHA1:   {1, 2, 840, 10045, 4, 1},
	x509.ECDSAWithSHA256: {1, 2, 840, 10045, 4, 3, 2},
	x509.ECDSAWithSHA384: {1, 2, 840, 10045, 4, 3, 3},
	x509.ECDSAWithSHA512: {1, 2, 840, 10045, 4, 3, 4},
}

var sigAlgHashes = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.ECDSAWithSHA1:   crypto.SHA1,
	x509.ECDSAWithSHA256: crypto.SHA256,
	x509.ECDSAWithSHA384: crypto.SHA384,
	x509.ECDSAWithSHA512: crypto.SHA512,
}

type certTemplate struct {
	version  int // 1 or 3; 0 means 3
	issuer   string
	subject  string
	spki     []byte
	isCA     *bool // nil: no basicConstraints extension
	keyUsage x509.KeyUsage
	sigAlg   x509.SignatureAlgorithm // 0 means ECDSAWithSHA256
}

func boolPtr(b bool) *bool { return &b }

func addName(b *cryptobyte.Builder, cn string) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 3})
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(cn)) })
			})
		})
	})
}

func addAlgorithm(b *cryptobyte.Builder, alg x509.SignatureAlgorithm) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(sigAlgOIDs[alg])
	})
}

func addExtension(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, critical bool, value func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1(cbasn1.OCTET_STRING, value)
	})
}

// keyUsageBits encodes ku as a DER named BIT STRING.
func keyUsageBits(b *cryptobyte.Builder, ku x509.KeyUsage) {
	var bs []byte
	for i := 0; i < 9; i++ {
		if ku&(1<<i) != 0 {
			for len(bs) <= i/8 {
				bs = append(bs, 0)
			}
			bs[i/8] |= 0x80 >> (i % 8)
		}
	}
	unused := 0
	for unused < 7 && bs[len(bs)-1]&(1<<unused) == 0 {
		unused++
	}
	b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
		b.AddUint8(uint8(unused))
		b.AddBytes(bs)
	})
}

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

// sign signs tbs with signer and wraps it as a Certificate or
// CertificateList.
func sign(t testing.TB, tbs []byte, alg x509.SignatureAlgorithm, signer crypto.Signer) []byte {
	t.Helper()
	h := sigAlgHashes[alg]
	hh := h.New()
	hh.Write(tbs)
	sig, err := signer.Sign(rand.Reader, hh.Sum(nil), h)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		addAlgorithm(b, alg)
		b.AddASN1BitString(sig)
	})
	return b.BytesOrPanic()
}

func makeCert(t testing.TB, tmpl certTemplate, signer crypto.Signer) []byte {
	t.Helper()
	if tmpl.sigAlg == 0 {
		tmpl.sigAlg = x509.ECDSAWithSHA256
	}
	if tmpl.version == 0 {
		tmpl.version = 3
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if tmpl.version == 3 {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddASN1Int64(2) })
		}
		b.AddASN1Int64(int64(len(tmpl.subject) + 1000))
		addAlgorithm(b, tmpl.sigAlg)
		addName(b, tmpl.issuer)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1UTCTime(notBefore)
			b.AddASN1UTCTime(notAfter)
		})
		addName(b, tmpl.subject)
		b.AddBytes(tmpl.spki)
		if tmpl.version == 3 && (tmpl.isCA != nil || tmpl.keyUsage != 0) {
			b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					if tmpl.isCA != nil {
						addExtension(b, asn1.ObjectIdentifier{2, 5, 29, 19}, true, func(b *cryptobyte.Builder) {
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
								if *tmpl.isCA {
									b.AddASN1Boolean(true)
								}
							})
						})
					}
					if tmpl.keyUsage != 0 {
						addExtension(b, asn1.ObjectIdentifier{2, 5, 29, 15}, true, func(b *cryptobyte.Builder) {
							keyUsageBits(b, tmpl.keyUsage)
						})
					}
				})
			})
		}
	})
	return sign(t, b.BytesOrPanic(), tmpl.sigAlg, signer)
}

// parseCert parses der. Without the ivory overlay, crypto/x509 can't
// parse a certificate with a Brainpool key; then parseCert fills in the
// fields the x509util functions read from tmpl and the DER, as the overlay's
// ParseCertificate would.
func parseCert(t testing.TB, der []byte, tmpl certTemplate) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err == nil {
		return c
	}
	if !strings.Contains(err.Error(), "unsupported elliptic curve") {
		t.Fatalf("ParseCertificate: %v", err)
	}
	c = &x509.Certificate{
		Raw:                     der,
		RawSubjectPublicKeyInfo: tmpl.spki,
		Version:                 tmpl.version,
		KeyUsage:                tmpl.keyUsage,
		PublicKeyAlgorithm:      x509.UnknownPublicKeyAlgorithm,
		SignatureAlgorithm:      tmpl.sigAlg,
	}
	if c.Version == 0 {
		c.Version = 3
	}
	if c.SignatureAlgorithm == 0 {
		c.SignatureAlgorithm = x509.ECDSAWithSHA256
	}
	if tmpl.isCA != nil {
		c.BasicConstraintsValid = true
		c.IsCA = *tmpl.isCA
	}
	c.RawTBSCertificate, c.Signature = splitSigned(t, der)
	return c
}

// splitSigned returns the TBS part and the signature of a Certificate or
// CertificateList.
func splitSigned(t testing.TB, der []byte) (tbs, sig []byte) {
	t.Helper()
	input := cryptobyte.String(der)
	var outer, raw cryptobyte.String
	var bits asn1.BitString
	if !input.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.ReadASN1Element(&raw, cbasn1.SEQUENCE) ||
		!outer.SkipASN1(cbasn1.SEQUENCE) || !outer.ReadASN1BitString(&bits) {
		t.Fatal("malformed signed structure")
	}
	return raw, bits.Bytes
}

// makeCRL returns a version 2 CRL from issuer with no entries.
func makeCRL(t testing.TB, issuer string, alg x509.SignatureAlgorithm, signer crypto.Signer) *x509.RevocationList {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		addAlgorithm(b, alg)
		addName(b, issuer)
		b.AddASN1UTCTime(notBefore)
		b.AddASN1UTCTime(notAfter)
	})
	der := sign(t, b.BytesOrPanic(), alg, signer)
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}
