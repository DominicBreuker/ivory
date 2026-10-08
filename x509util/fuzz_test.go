package x509util

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
)

// FuzzParsePKIXPublicKey checks that ParsePKIXPublicKey never panics,
// that every Brainpool key it accepts is canonical (marshaling gives the
// input back), and that it agrees with crypto/x509 on all other inputs.
func FuzzParsePKIXPublicKey(f *testing.F) {
	for _, c := range []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()} {
		k, _ := brainpool.GenerateKey(c)
		spki, _ := MarshalPKIXPublicKey(k.PublicKey())
		f.Add(spki)
	}
	f.Add(readPEM(f, "p256-ca.pem").Bytes)
	f.Fuzz(func(t *testing.T, der []byte) {
		pub, err := ParsePKIXPublicKey(der)
		if bp, ok := pub.(*brainpool.PublicKey); ok {
			if err != nil {
				t.Fatalf("key and error: %v", err)
			}
			out, err := MarshalPKIXPublicKey(bp)
			if err != nil || !bytes.Equal(out, der) {
				t.Fatalf("accepted non-canonical SPKI %x (re-encoded %x, %v)", der, out, err)
			}
			return
		}
		if err != nil {
			return
		}
		// Not a Brainpool key: must be what crypto/x509 returns.
		want, werr := x509.ParsePKIXPublicKey(der)
		if werr != nil {
			t.Fatalf("crypto/x509 rejects what ParsePKIXPublicKey accepted: %v", werr)
		}
		type equaler interface{ Equal(any) bool }
		if e, ok := want.(equaler); ok && !e.Equal(pub) {
			t.Fatalf("different key than crypto/x509: %T, %T", pub, want)
		}
	})
}

// FuzzParsePrivateKey checks that the private key parsers never panic and
// that an accepted Brainpool key round-trips through its marshal function.
func FuzzParsePrivateKey(f *testing.F) {
	for _, c := range []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()} {
		k, _ := brainpool.GenerateKey(c)
		p8, _ := MarshalPKCS8PrivateKey(k)
		sec1, _ := MarshalECPrivateKey(k)
		f.Add(p8)
		f.Add(sec1)
	}
	f.Add(readPEM(f, "p256-ca.key").Bytes)
	f.Fuzz(func(t *testing.T, der []byte) {
		if k, err := ParseECPrivateKey(der); err == nil {
			out, _ := MarshalECPrivateKey(k)
			k2, err := ParseECPrivateKey(out)
			if err != nil || !k2.Equal(k) {
				t.Fatalf("SEC 1 round trip failed: %v", err)
			}
		}
		if k, err := ParsePKCS8PrivateKey(der); err == nil {
			if bk, ok := k.(*brainpool.PrivateKey); ok {
				out, _ := MarshalPKCS8PrivateKey(bk)
				k2, err := ParsePKCS8PrivateKey(out)
				if err != nil || !bk.Equal(k2) {
					t.Fatalf("PKCS #8 round trip failed: %v", err)
				}
			}
		}
	})
}
