//go:build ivory

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// identityFlags name the local TLS identities: pairs of a certificate
// chain and a private key, in PEM files.
type identityFlags struct {
	certs, keys listFlag
}

func (f *identityFlags) register(fs *flag.FlagSet, what string) {
	fs.Var(&f.certs, "cert", what+" certificate chain (PEM, leaf first); repeatable, one per -key")
	fs.Var(&f.keys, "key", "private key for the preceding -cert (PEM, PKCS #8 or SEC 1; Brainpool, NIST ECDSA, RSA or Ed25519); repeatable")
}

func (f *identityFlags) load() ([]tls.Certificate, error) {
	if len(f.certs) != len(f.keys) {
		return nil, fmt.Errorf("%d -cert but %d -key flags", len(f.certs), len(f.keys))
	}
	var out []tls.Certificate
	for i := range f.certs {
		c, err := loadIdentity(f.certs[i], f.keys[i])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// loadIdentity loads a certificate chain and its key. Keys of crypto/tls
// (RSA, NIST ECDSA, Ed25519) and Brainpool keys work; the two may be in
// the same file, such as the output of openssl pkcs12 -nodes.
func loadIdentity(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err == nil {
		return c, nil
	}
	c, bpErr := tlsutil.X509KeyPair(certPEM, keyPEM)
	if bpErr == nil {
		return c, nil
	}
	return tls.Certificate{}, fmt.Errorf("%s, %s: %v (as a Brainpool key: %v)", certFile, keyFile, err, bpErr)
}

// generateIdentities returns self-signed test identities for the names
// (host names or IP addresses): brainpoolP256r1, P-256 and RSA 2048, so
// that a client gets a certificate whatever it supports.
func generateIdentities(names []string) ([]tls.Certificate, error) {
	tmpl := func() *x509.Certificate {
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
		t := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "ivory test identity", Organization: []string{"ivory test (not trusted)"}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		for _, n := range names {
			if ip := net.ParseIP(n); ip != nil {
				t.IPAddresses = append(t.IPAddresses, ip)
			} else {
				t.DNSNames = append(t.DNSNames, n)
			}
		}
		return t
	}
	bp, err := brainpool.GenerateKey(brainpool.P256r1())
	if err != nil {
		return nil, err
	}
	bpDER, err := selfSignedBrainpool(tmpl(), bp)
	if err != nil {
		return nil, err
	}
	bpCert, err := tlsutil.Certificate([][]byte{bpDER}, tlsutil.NewSigner(bp))
	if err != nil {
		return nil, err
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ecCert, err := selfSigned(tmpl(), ec)
	if err != nil {
		return nil, err
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rt := tmpl()
	rt.KeyUsage |= x509.KeyUsageKeyEncipherment
	rsaCert, err := selfSigned(rt, rk)
	if err != nil {
		return nil, err
	}
	return []tls.Certificate{bpCert, ecCert, rsaCert}, nil
}

func selfSigned(tmpl *x509.Certificate, key crypto.Signer) (tls.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// selfSignedBrainpool returns a self-signed certificate for a Brainpool
// key. crypto/x509 can't sign with Brainpool keys, so it builds the
// certificate with a placeholder P-256 key; then the Brainpool public key
// replaces the placeholder's and the Brainpool key signs the result
// (ecdsa-with-SHA256, the algorithm the placeholder set).
func selfSignedBrainpool(tmpl *x509.Certificate, key *brainpool.PrivateKey) ([]byte, error) {
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, placeholder.Public(), placeholder)
	if err != nil {
		return nil, err
	}
	spki, err := x509util.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return nil, err
	}
	in := cryptobyte.String(der)
	var outer, tbs, alg cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!outer.ReadASN1Element(&alg, cbasn1.SEQUENCE) {
		return nil, errors.New("malformed certificate")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version, serial, signature, issuer, validity, subject,
		// subjectPublicKeyInfo, ...
		for i := 0; !tbs.Empty(); i++ {
			var field cryptobyte.String
			if !tbs.ReadAnyASN1Element(&field, nil) {
				b.SetError(errors.New("malformed TBSCertificate"))
				return
			}
			if i == 6 {
				field = spki
			}
			b.AddBytes(field)
		}
	})
	newTBS, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(newTBS)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	b = cryptobyte.Builder{}
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddBytes(alg)
		b.AddASN1BitString(sig)
	})
	return b.Bytes()
}
