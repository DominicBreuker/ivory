package x509util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const pki = "../testdata/pki"

func readPEM(t testing.TB, name string) *pem.Block {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pki, name))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s: no PEM data", name)
	}
	return block
}

func openssl(t testing.TB, args ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	cmd := exec.Command("openssl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, stderr.Bytes())
	}
	return out
}

var brainpoolKeys = []struct {
	name  string
	curve brainpool.Curve
}{
	{"bp256-server", brainpool.P256r1()},
	{"bp256-ca", brainpool.P256r1()},
	{"bp384-client", brainpool.P384r1()},
	{"bp512-server", brainpool.P512r1()},
}

func TestOIDs(t *testing.T) {
	for _, tt := range []struct {
		c   brainpool.Curve
		oid string
	}{
		{brainpool.P256r1(), "1.3.36.3.3.2.8.1.1.7"},
		{brainpool.P384r1(), "1.3.36.3.3.2.8.1.1.11"},
		{brainpool.P512r1(), "1.3.36.3.3.2.8.1.1.13"},
	} {
		if got := OIDForCurve(tt.c).String(); got != tt.oid {
			t.Errorf("OIDForCurve(%v) = %s, want %s", tt.c, got, tt.oid)
		}
		if CurveForOID(OIDForCurve(tt.c)) != tt.c {
			t.Errorf("CurveForOID(%s) != %v", tt.oid, tt.c)
		}
	}
	if CurveForOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) != nil {
		t.Error("CurveForOID(P-256) is not nil")
	}
}

// TestKeysFromOpenSSL parses the OpenSSL-made test keys in PKCS #8 and
// SEC 1 form and their public keys, and checks that marshaling reproduces
// OpenSSL's bytes.
func TestKeysFromOpenSSL(t *testing.T) {
	for _, tt := range brainpoolKeys {
		t.Run(tt.name, func(t *testing.T) {
			p8 := readPEM(t, tt.name+".key")
			k, err := ParsePKCS8PrivateKey(p8.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			key, ok := k.(*brainpool.PrivateKey)
			if !ok || key.Curve() != tt.curve {
				t.Fatalf("ParsePKCS8PrivateKey returned %T", k)
			}
			if der, err := MarshalPKCS8PrivateKey(key); err != nil || !bytes.Equal(der, p8.Bytes) {
				t.Errorf("MarshalPKCS8PrivateKey differs from OpenSSL's file: %v", err)
			}

			sec1 := readPEM(t, tt.name+".sec1.pem")
			k1, err := ParseECPrivateKey(sec1.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !k1.Equal(key) {
				t.Error("the SEC 1 and PKCS #8 files hold different keys")
			}
			if der, err := MarshalECPrivateKey(k1); err != nil || !bytes.Equal(der, sec1.Bytes) {
				t.Errorf("MarshalECPrivateKey differs from OpenSSL's file: %v", err)
			}

			spki := openssl(t, "pkey", "-in", filepath.Join(pki, tt.name+".key"), "-pubout", "-outform", "DER")
			pub, err := ParsePKIXPublicKey(spki)
			if err != nil {
				t.Fatal(err)
			}
			if bp, ok := pub.(*brainpool.PublicKey); !ok || !bp.Equal(key.PublicKey()) {
				t.Errorf("ParsePKIXPublicKey returned %T, not the key's public key", pub)
			}
			if der, err := MarshalPKIXPublicKey(key.PublicKey()); err != nil || !bytes.Equal(der, spki) {
				t.Errorf("MarshalPKIXPublicKey differs from OpenSSL's: %v", err)
			}
		})
	}
}

// TestOtherKeysDelegate checks that non-Brainpool keys come back as
// crypto/x509 returns them.
func TestOtherKeysDelegate(t *testing.T) {
	p256, err := ParsePKCS8PrivateKey(readPEM(t, "p256-ca.key").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := p256.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("P-256 PKCS #8 key parsed as %T", p256)
	}
	rsaKey, err := ParsePKCS8PrivateKey(readPEM(t, "rsa-ca.key").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rsaKey.(*rsa.PrivateKey); !ok {
		t.Errorf("RSA PKCS #8 key parsed as %T", rsaKey)
	}
	spki, err := x509.MarshalPKIXPublicKey(&p256.(*ecdsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("P-256 SPKI parsed as %T", pub)
	}
	if _, err := ParseECPrivateKey(readPEM(t, "p256-ca.sec1.pem").Bytes); err == nil {
		t.Error("ParseECPrivateKey accepted a P-256 key")
	}
	// secp256k1, which crypto/x509 doesn't support either.
	k1 := spkiWithParams(t, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
	}, append([]byte{4}, make([]byte, 64)...))
	if _, err := ParsePKIXPublicKey(k1); err == nil {
		t.Error("ParsePKIXPublicKey accepted a secp256k1 key")
	}
}

// spkiWithParams builds an id-ecPublicKey SubjectPublicKeyInfo.
func spkiWithParams(t testing.TB, params func(*cryptobyte.Builder), point []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidPublicKeyECDSA)
			if params != nil {
				params(b)
			}
		})
		b.AddASN1BitString(point)
	})
	return b.BytesOrPanic()
}

func TestParsePKIXPublicKeyInvalid(t *testing.T) {
	k, _ := brainpool.GenerateKey(brainpool.P256r1())
	point := k.PublicKey().Bytes()
	named := func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(OIDBrainpoolP256r1) }
	good := spkiWithParams(t, named, point)
	if _, err := ParsePKIXPublicKey(good); err != nil {
		t.Fatal(err)
	}
	offCurve := bytes.Clone(point)
	offCurve[len(offCurve)-1] ^= 1
	compressed := append([]byte{2 | point[len(point)-1]&1}, point[1:33]...)
	unusedBits := bytes.Clone(good)
	unusedBits[len(unusedBits)-len(point)-1] = 4 // the BIT STRING's unused-bits byte
	cases := map[string][]byte{
		"off curve":          spkiWithParams(t, named, offCurve),
		"compressed point":   spkiWithParams(t, named, compressed),
		"P384r1 OID":         spkiWithParams(t, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(OIDBrainpoolP384r1) }, point),
		"NULL parameters":    spkiWithParams(t, func(b *cryptobyte.Builder) { b.AddASN1NULL() }, point),
		"no parameters":      spkiWithParams(t, nil, point),
		"OID and more":       spkiWithParams(t, func(b *cryptobyte.Builder) { named(b); b.AddASN1NULL() }, point),
		"trailing data":      append(bytes.Clone(good), 0),
		"unused bits":        unusedBits,
		"empty":              nil,
		"truncated":          good[:len(good)-1],
		"point at infinity":  spkiWithParams(t, named, []byte{0}),
		"explicit (OpenSSL)": explicitSPKI(t),
	}
	for name, der := range cases {
		if der == nil && name == "explicit (OpenSSL)" {
			continue
		}
		if pub, err := ParsePKIXPublicKey(der); err == nil {
			t.Errorf("%s: parsed as %T", name, pub)
		}
	}
}

// explicitSPKI returns a brainpoolP256r1 key with explicit curve
// parameters, from OpenSSL, or nil without OpenSSL.
func explicitSPKI(t testing.TB) []byte {
	if _, err := exec.LookPath("openssl"); err != nil {
		return nil
	}
	return openssl(t, "ec", "-in", filepath.Join(pki, "bp256-server.key"), "-param_enc", "explicit", "-pubout", "-outform", "DER")
}

func TestParseECPrivateKeyInvalid(t *testing.T) {
	good := readPEM(t, "bp256-server.sec1.pem").Bytes
	k, err := ParseECPrivateKey(good)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := brainpool.GenerateKey(brainpool.P256r1())
	build := func(version int64, d []byte, params func(*cryptobyte.Builder), pub []byte) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(version)
			b.AddASN1OctetString(d)
			if params != nil {
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), params)
			}
			if pub != nil {
				b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddASN1BitString(pub) })
			}
		})
		return b.BytesOrPanic()
	}
	named := func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(OIDBrainpoolP256r1) }
	d := k.Bytes()

	// Accepted: no public key; leading zeros added or removed.
	for name, der := range map[string][]byte{
		"without public key": build(1, d, named, nil),
		"extra leading zero": build(1, append([]byte{0}, d...), named, nil),
	} {
		got, err := ParseECPrivateKey(der)
		if err != nil || !got.Equal(k) {
			t.Errorf("%s: %v", name, err)
		}
	}
	short := make([]byte, 32)
	short[31] = 5
	if got, err := ParseECPrivateKey(build(1, short[30:], named, nil)); err != nil || got.Bytes()[31] != 5 {
		t.Errorf("stripped leading zeros: %v", err)
	}

	var explicit []byte
	if _, err := exec.LookPath("openssl"); err == nil {
		block, _ := pem.Decode(openssl(t, "ec", "-in", filepath.Join(pki, "bp256-server.key"), "-param_enc", "explicit"))
		explicit = block.Bytes
	}
	for name, der := range map[string][]byte{
		"no parameters":    build(1, d, nil, k.PublicKey().Bytes()),
		"version 0":        build(0, d, named, nil),
		"version 2":        build(2, d, named, nil),
		"wrong public key": build(1, d, named, other.PublicKey().Bytes()),
		"d = 0":            build(1, make([]byte, 32), named, nil),
		"d too long":       build(1, append([]byte{1}, d...), named, nil),
		"P384r1 OID":       build(1, d, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(OIDBrainpoolP384r1) }, k.PublicKey().Bytes()),
		"P-256 OID": build(1, d, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
		}, nil),
		"NULL parameters":    build(1, d, func(b *cryptobyte.Builder) { b.AddASN1NULL() }, nil),
		"trailing data":      append(bytes.Clone(good), 0),
		"explicit (OpenSSL)": explicit,
	} {
		if der == nil {
			continue
		}
		if _, err := ParseECPrivateKey(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePKCS8Variants(t *testing.T) {
	k, _ := brainpool.GenerateKey(brainpool.P384r1())
	inner := func(withParams bool, oid asn1.ObjectIdentifier) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			b.AddASN1OctetString(k.Bytes())
			if withParams {
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oid) })
			}
		})
		return b.BytesOrPanic()
	}
	build := func(version int64, in []byte, extra func(*cryptobyte.Builder)) []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(version)
			addECAlgorithmIdentifier(b, k.Curve())
			b.AddASN1OctetString(in)
			if extra != nil {
				extra(b)
			}
		})
		return b.BytesOrPanic()
	}
	pubField := func(p []byte) func(*cryptobyte.Builder) {
		return func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddUint8(0); b.AddBytes(p) })
		}
	}
	attrs := func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {})
	}
	other, _ := brainpool.GenerateKey(brainpool.P384r1())
	for _, tt := range []struct {
		name string
		der  []byte
		ok   bool
	}{
		{"plain", build(0, inner(false, nil), nil), true},
		{"inner parameters", build(0, inner(true, OIDBrainpoolP384r1), nil), true},
		{"attributes", build(0, inner(false, nil), attrs), true},
		{"v2 with public key", build(1, inner(false, nil), pubField(k.PublicKey().Bytes())), true},
		{"v2 with wrong public key", build(1, inner(false, nil), pubField(other.PublicKey().Bytes())), false},
		{"v1 with public key", build(0, inner(false, nil), pubField(k.PublicKey().Bytes())), false},
		{"version 2", build(2, inner(false, nil), nil), false},
		{"inner curve mismatch", build(0, inner(true, OIDBrainpoolP256r1), nil), false},
		{"trailing data", append(build(0, inner(false, nil), nil), 0), false},
	} {
		got, err := ParsePKCS8PrivateKey(tt.der)
		if tt.ok && (err != nil || !got.(*brainpool.PrivateKey).Equal(k)) || !tt.ok && err == nil {
			t.Errorf("%s: got %T, %v; want ok = %v", tt.name, got, err, tt.ok)
		}
	}
}

func TestCheckSignature(t *testing.T) {
	k, _ := brainpool.GenerateKey(brainpool.P256r1())
	signed := []byte("tbs")
	sig := func(h crypto.Hash, signer crypto.Signer) []byte {
		hh := h.New()
		hh.Write(signed)
		s, err := signer.Sign(rand.Reader, hh.Sum(nil), h)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, tt := range []struct {
		name    string
		algo    x509.SignatureAlgorithm
		sig     []byte
		pub     any
		wantErr error // nil: success; errAny: any error
	}{
		{"SHA-256", x509.ECDSAWithSHA256, sig(crypto.SHA256, k), k.PublicKey(), nil},
		{"SHA-384", x509.ECDSAWithSHA384, sig(crypto.SHA384, k), k.PublicKey(), nil},
		{"SHA-512", x509.ECDSAWithSHA512, sig(crypto.SHA512, k), k.PublicKey(), nil},
		{"hash mismatch", x509.ECDSAWithSHA256, sig(crypto.SHA384, k), k.PublicKey(), errAny},
		{"SHA-1", x509.ECDSAWithSHA1, sig(crypto.SHA1, k), k.PublicKey(), x509.InsecureAlgorithmError(x509.ECDSAWithSHA1)},
		{"RSA algorithm", x509.SHA256WithRSA, sig(crypto.SHA256, k), k.PublicKey(), x509.ErrUnsupportedAlgorithm},
		{"Ed25519 algorithm", x509.PureEd25519, sig(crypto.SHA256, k), k.PublicKey(), x509.ErrUnsupportedAlgorithm},
		{"P-256", x509.ECDSAWithSHA256, sig(crypto.SHA256, p256), &p256.PublicKey, nil},
		{"P-256 SHA-1", x509.ECDSAWithSHA1, sig(crypto.SHA1, p256), &p256.PublicKey, x509.InsecureAlgorithmError(x509.ECDSAWithSHA1)},
		{"P-256 signature, Brainpool key", x509.ECDSAWithSHA256, sig(crypto.SHA256, p256), k.PublicKey(), errAny},
		{"unknown key type", x509.ECDSAWithSHA256, sig(crypto.SHA256, k), "key", x509.ErrUnsupportedAlgorithm},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSignature(tt.algo, signed, tt.sig, tt.pub)
			checkErr(t, err, tt.wantErr)
		})
	}
}

var errAny = errors.New("any error")

func checkErr(t *testing.T, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Errorf("err = %v, want success", err)
	case want == errAny && err == nil:
		t.Error("succeeded, want an error")
	case want != nil && want != errAny && !errors.Is(err, want):
		var ie x509.InsecureAlgorithmError
		var ce x509.ConstraintViolationError
		if errors.As(want, &ie) && errors.As(err, &ie) || errors.As(want, &ce) && errors.As(err, &ce) {
			return
		}
		t.Errorf("err = %v, want %v", err, want)
	}
}

type keyPair struct {
	signer crypto.Signer
	spki   []byte
}

func newBrainpoolPair(t testing.TB, c brainpool.Curve) keyPair {
	k, err := brainpool.GenerateKey(c)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{k, spki}
}

func newP256Pair(t testing.TB) keyPair {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{k, spki}
}

func TestCheckCertificateSignatureFrom(t *testing.T) {
	bp256 := newBrainpoolPair(t, brainpool.P256r1())
	bp384 := newBrainpoolPair(t, brainpool.P384r1())
	bp512 := newBrainpoolPair(t, brainpool.P512r1())
	p256 := newP256Pair(t)
	leafBP := newBrainpoolPair(t, brainpool.P256r1())
	leafP256 := newP256Pair(t)

	ca := func(name string, kp keyPair, isCA *bool, ku x509.KeyUsage, version int) *x509.Certificate {
		tmpl := certTemplate{version: version, issuer: name, subject: name, spki: kp.spki, isCA: isCA, keyUsage: ku}
		return parseCert(t, makeCert(t, tmpl, kp.signer), tmpl)
	}
	leaf := func(issuer string, kp keyPair, signer crypto.Signer, alg x509.SignatureAlgorithm) *x509.Certificate {
		tmpl := certTemplate{issuer: issuer, subject: "leaf", spki: kp.spki, isCA: boolPtr(false), keyUsage: x509.KeyUsageDigitalSignature, sigAlg: alg}
		return parseCert(t, makeCert(t, tmpl, signer), tmpl)
	}
	caBP := ca("bp CA", bp256, boolPtr(true), x509.KeyUsageCertSign|x509.KeyUsageCRLSign, 3)
	tampered := leaf("bp CA", leafP256, bp256.signer, x509.ECDSAWithSHA256)
	tampered.Signature = bytes.Clone(tampered.Signature)
	tampered.Signature[len(tampered.Signature)-1] ^= 1
	tamperedTBS := leaf("bp CA", leafP256, bp256.signer, x509.ECDSAWithSHA256)
	tamperedTBS.RawTBSCertificate = bytes.Clone(tamperedTBS.RawTBSCertificate)
	tamperedTBS.RawTBSCertificate[len(tamperedTBS.RawTBSCertificate)-1] ^= 1

	for _, tt := range []struct {
		name          string
		child, parent *x509.Certificate
		wantErr       error
	}{
		{"Brainpool CA, P-256 leaf", leaf("bp CA", leafP256, bp256.signer, x509.ECDSAWithSHA256), caBP, nil},
		{"Brainpool CA, Brainpool leaf", leaf("bp CA", leafBP, bp256.signer, x509.ECDSAWithSHA256), caBP, nil},
		{"SHA-384", leaf("bp CA", leafBP, bp256.signer, x509.ECDSAWithSHA384), caBP, nil},
		{"SHA-512", leaf("bp CA", leafBP, bp256.signer, x509.ECDSAWithSHA512), caBP, nil},
		{"bp384 CA", leaf("c", leafBP, bp384.signer, x509.ECDSAWithSHA384), ca("c", bp384, boolPtr(true), x509.KeyUsageCertSign, 3), nil},
		{"bp512 CA", leaf("c", leafBP, bp512.signer, x509.ECDSAWithSHA512), ca("c", bp512, boolPtr(true), x509.KeyUsageCertSign, 3), nil},
		{"CA without keyUsage", leaf("c", leafBP, bp256.signer, x509.ECDSAWithSHA256), ca("c", bp256, boolPtr(true), 0, 3), nil},
		{"version 1 CA", leaf("c", leafBP, bp256.signer, x509.ECDSAWithSHA256), ca("c", bp256, nil, 0, 1), nil},
		{"P-256 CA, Brainpool leaf", leaf("c", leafBP, p256.signer, x509.ECDSAWithSHA256), ca("c", p256, boolPtr(true), x509.KeyUsageCertSign, 3), nil},
		{"tampered signature", tampered, caBP, errAny},
		{"tampered TBS", tamperedTBS, caBP, errAny},
		{"other CA key", leaf("bp CA", leafBP, bp384.signer, x509.ECDSAWithSHA256), caBP, errAny},
		{"SHA-1", leaf("bp CA", leafBP, bp256.signer, x509.ECDSAWithSHA1), caBP, x509.InsecureAlgorithmError(x509.ECDSAWithSHA1)},
		{"parent cA = FALSE", leaf("c", leafBP, bp256.signer, x509.ECDSAWithSHA256), ca("c", bp256, boolPtr(false), x509.KeyUsageCertSign, 3), x509.ConstraintViolationError{}},
		{"v3 parent without basicConstraints", leaf("c", leafBP, bp256.signer, x509.ECDSAWithSHA256), ca("c", bp256, nil, x509.KeyUsageCertSign, 3), x509.ConstraintViolationError{}},
		{"parent without keyCertSign", leaf("c", leafBP, bp256.signer, x509.ECDSAWithSHA256), ca("c", bp256, boolPtr(true), x509.KeyUsageCRLSign, 3), x509.ConstraintViolationError{}},
		{"P-256 parent, tampered", func() *x509.Certificate {
			c := leaf("c", leafBP, p256.signer, x509.ECDSAWithSHA256)
			c.Signature = bytes.Clone(c.Signature)
			c.Signature[len(c.Signature)-1] ^= 1
			return c
		}(), ca("c", p256, boolPtr(true), x509.KeyUsageCertSign, 3), errAny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, CheckCertificateSignatureFrom(tt.child, tt.parent), tt.wantErr)
		})
	}
}

// TestCheckCertificateSignatureFromOpenSSL checks OpenSSL-made
// certificates: a P-256 leaf under the Brainpool CA (its parent is built
// from the CA certificate's fields when crypto/x509 can't parse it) and an
// RSA chain through crypto/x509.
func TestCheckCertificateSignatureFromOpenSSL(t *testing.T) {
	leaf, err := x509.ParseCertificate(readPEM(t, "p256-under-bp256.pem").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caDER := readPEM(t, "bp256-ca.pem").Bytes
	caKey, err := ParsePKCS8PrivateKey(readPEM(t, "bp256-ca.key").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := MarshalPKIXPublicKey(caKey.(*brainpool.PrivateKey).PublicKey())
	ca := parseCert(t, caDER, certTemplate{spki: spki, isCA: boolPtr(true), keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	if err := CheckCertificateSignatureFrom(leaf, ca); err != nil {
		t.Errorf("p256-under-bp256: %v", err)
	}
	evilDER := readPEM(t, "bp256-evil-ca.pem").Bytes
	evilKey, _ := ParsePKCS8PrivateKey(readPEM(t, "bp256-evil-ca.key").Bytes)
	evilSPKI, _ := MarshalPKIXPublicKey(evilKey.(*brainpool.PrivateKey).PublicKey())
	evil := parseCert(t, evilDER, certTemplate{spki: evilSPKI, isCA: boolPtr(true), keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	if err := CheckCertificateSignatureFrom(leaf, evil); err == nil {
		t.Error("the evil CA's key verified the leaf")
	}

	rsaLeaf, _ := x509.ParseCertificate(readPEM(t, "rsa-server.pem").Bytes)
	rsaCA, _ := x509.ParseCertificate(readPEM(t, "rsa-ca.pem").Bytes)
	if err := CheckCertificateSignatureFrom(rsaLeaf, rsaCA); err != nil {
		t.Errorf("RSA chain: %v", err)
	}
	if err := CheckCertificateSignatureFrom(rsaLeaf, ca); err == nil {
		t.Error("the Brainpool CA verified the RSA leaf")
	}
}

func TestCheckCRLSignatureFrom(t *testing.T) {
	signer := newBrainpoolPair(t, brainpool.P256r1())
	p256 := newP256Pair(t)
	cert := func(kp keyPair, isCA *bool, ku x509.KeyUsage) *x509.Certificate {
		tmpl := certTemplate{issuer: "CA", subject: "CRL signer", spki: kp.spki, isCA: isCA, keyUsage: ku}
		return parseCert(t, makeCert(t, tmpl, kp.signer), tmpl)
	}
	// C.GEM.CRL: cA = FALSE, keyUsage cRLSign (GS-A_4939).
	gemCRL := cert(signer, boolPtr(false), x509.KeyUsageCRLSign)
	crl := makeCRL(t, "CRL signer", x509.ECDSAWithSHA256, signer.signer)
	tamperedCRL := makeCRL(t, "CRL signer", x509.ECDSAWithSHA256, signer.signer)
	tamperedCRL.Signature = bytes.Clone(tamperedCRL.Signature)
	tamperedCRL.Signature[len(tamperedCRL.Signature)-1] ^= 1
	p256Signer := cert(p256, boolPtr(false), x509.KeyUsageCRLSign)
	p256CRL := makeCRL(t, "CRL signer", x509.ECDSAWithSHA384, p256.signer)

	for _, tt := range []struct {
		name    string
		crl     *x509.RevocationList
		issuer  *x509.Certificate
		wantErr error
	}{
		{"C.GEM.CRL signer", crl, gemCRL, nil},
		{"SHA-512", makeCRL(t, "CRL signer", x509.ECDSAWithSHA512, signer.signer), gemCRL, nil},
		{"CA with cRLSign", crl, cert(signer, boolPtr(true), x509.KeyUsageCRLSign|x509.KeyUsageCertSign), nil},
		{"no keyUsage", crl, cert(signer, boolPtr(false), 0), nil},
		{"keyUsage without cRLSign", crl, cert(signer, boolPtr(false), x509.KeyUsageDigitalSignature), x509.ConstraintViolationError{}},
		{"tampered", tamperedCRL, gemCRL, errAny},
		{"other key", crl, cert(newBrainpoolPair(t, brainpool.P256r1()), boolPtr(false), x509.KeyUsageCRLSign), errAny},
		{"SHA-1", makeCRL(t, "CRL signer", x509.ECDSAWithSHA1, signer.signer), gemCRL, x509.InsecureAlgorithmError(x509.ECDSAWithSHA1)},
		{"P-256 signer, cA = FALSE", p256CRL, p256Signer, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, CheckCRLSignatureFrom(tt.crl, tt.issuer), tt.wantErr)
		})
	}

	// crypto/x509 rejects the same CRL from a signer with cA = FALSE,
	// whatever its key: the reason for CheckCRLSignatureFrom.
	var ce x509.ConstraintViolationError
	if err := p256CRL.CheckSignatureFrom(p256Signer); !errors.As(err, &ce) {
		t.Errorf("x509: RevocationList.CheckSignatureFrom = %v, want ConstraintViolationError", err)
	}
}

// TestCheckCRLSignatureFromOpenSSL checks a CRL that OpenSSL signs with a
// Brainpool CRL signer certificate with cA = FALSE (as C.GEM.CRL), issued
// by the test CA.
func TestCheckCRLSignatureFromOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "signer.key")
	csr := filepath.Join(dir, "signer.csr")
	crt := filepath.Join(dir, "signer.pem")
	ext := filepath.Join(dir, "ext.cnf")
	cfg := filepath.Join(dir, "ca.cnf")
	write := func(name, s string) {
		if err := os.WriteFile(name, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,cRLSign\nsubjectKeyIdentifier=hash\n")
	write(filepath.Join(dir, "index.txt"), "")
	write(cfg, `[ca]
default_ca = ca
[ca]
database = `+filepath.Join(dir, "index.txt")+`
crlnumber = `+filepath.Join(dir, "crlnumber")+`
default_md = sha256
default_crl_days = 30
`)
	write(filepath.Join(dir, "crlnumber"), "01\n")
	openssl(t, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1", "-out", key)
	openssl(t, "req", "-new", "-key", key, "-subj", "/CN=ivory test CRL signer", "-out", csr)
	openssl(t, "x509", "-req", "-in", csr, "-CA", filepath.Join(pki, "bp256-ca.pem"), "-CAkey", filepath.Join(pki, "bp256-ca.key"),
		"-set_serial", "4242", "-days", "30", "-extfile", ext, "-out", crt)
	crlPEM := openssl(t, "ca", "-gencrl", "-config", cfg, "-keyfile", key, "-cert", crt)
	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("no CRL in OpenSSL output:\n%s", crlPEM)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(key)
	kb, _ := pem.Decode(keyPEM)
	k, err := ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := MarshalPKIXPublicKey(k.(*brainpool.PrivateKey).PublicKey())
	crtPEM, _ := os.ReadFile(crt)
	cb, _ := pem.Decode(crtPEM)
	signerCert := parseCert(t, cb.Bytes, certTemplate{spki: spki, isCA: boolPtr(false), keyUsage: x509.KeyUsageCRLSign})
	if signerCert.IsCA || !signerCert.BasicConstraintsValid || signerCert.KeyUsage != x509.KeyUsageCRLSign {
		t.Fatalf("signer certificate: IsCA %v, BasicConstraintsValid %v, KeyUsage %v", signerCert.IsCA, signerCert.BasicConstraintsValid, signerCert.KeyUsage)
	}
	if err := CheckCRLSignatureFrom(crl, signerCert); err != nil {
		t.Errorf("OpenSSL CRL: %v", err)
	}
	if !strings.Contains(crl.Issuer.String(), "ivory test CRL signer") {
		t.Errorf("CRL issuer %v", crl.Issuer)
	}

	// The CRL signer certificate itself is signed by the Brainpool CA.
	caKey, _ := ParsePKCS8PrivateKey(readPEM(t, "bp256-ca.key").Bytes)
	caSPKI, _ := MarshalPKIXPublicKey(caKey.(*brainpool.PrivateKey).PublicKey())
	ca := parseCert(t, readPEM(t, "bp256-ca.pem").Bytes, certTemplate{spki: caSPKI, isCA: boolPtr(true), keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
	if err := CheckCertificateSignatureFrom(signerCert, ca); err != nil {
		t.Errorf("CRL signer certificate: %v", err)
	}
}

func TestPublicKey(t *testing.T) {
	kp := newBrainpoolPair(t, brainpool.P384r1())
	tmpl := certTemplate{issuer: "x", subject: "x", spki: kp.spki, isCA: boolPtr(true), keyUsage: x509.KeyUsageCertSign}
	c := parseCert(t, makeCert(t, tmpl, kp.signer), tmpl)
	pub, err := PublicKey(c)
	if err != nil {
		t.Fatal(err)
	}
	if !kp.signer.Public().(*brainpool.PublicKey).Equal(pub) {
		t.Errorf("PublicKey = %T", pub)
	}
	rsaCA, _ := x509.ParseCertificate(readPEM(t, "rsa-ca.pem").Bytes)
	if pub, err := PublicKey(rsaCA); err != nil || pub != rsaCA.PublicKey {
		t.Errorf("PublicKey(RSA) = %T, %v", pub, err)
	}
}
