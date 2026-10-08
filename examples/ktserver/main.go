//go:build ivory

// Command ktserver is an example TLS server of an eHealth card terminal
// (eHealth-KT) on the SICCT channel, built with package ti.
//
// It holds an RSA and a Brainpool identity (A_17089-03) and presents the one
// that fits the client's cipher suites (A_22453). It requests a client
// certificate (A_22455), checks it against the stored Konnektor CA
// certificates in two levels (A_22888), and logs the state of the A_22456
// state machine instead of failing the handshake (A_22890). Build it with
// the ivory overlay, profile kt, for the KT-only behavior: renegotiation is
// refused with no_renegotiation (P0, GS-A_5524), the CertificateRequest
// carries one certificate type (P6, A_22454).
//
// Usage, with the test PKI of this repository:
//
//	ktserver -addr 127.0.0.1:4742 \
//		-ecc-cert testdata/pki/bp256-server.pem -ecc-key testdata/pki/bp256-server.key \
//		-rsa-cert testdata/pki/rsa-server.pem -rsa-key testdata/pki/rsa-server.key \
//		-konnektor-ca testdata/pki/bp256-ca.pem -any-policy
//
// -any-policy skips the C.SAK.AUT policy check: the test PKI has no TI
// policies. A real terminal keeps the check, and its card signs: use
// tlsutil.RawSigner for the gSMC-KT key.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4742", "listen `address`")
	eccCert := flag.String("ecc-cert", "", "Brainpool identity certificate (PEM)")
	eccKey := flag.String("ecc-key", "", "Brainpool identity key (PEM, PKCS #8 or SEC 1)")
	rsaCert := flag.String("rsa-cert", "", "RSA identity certificate (PEM)")
	rsaKey := flag.String("rsa-key", "", "RSA identity key (PEM)")
	cas := flag.String("konnektor-ca", "", "comma-separated PEM files with the CA certificates that may issue Konnektor certificates")
	paired := flag.String("paired", "", "comma-separated SHA-256 hashes (hex) of paired Konnektor SubjectPublicKeyInfos")
	anyPolicy := flag.Bool("any-policy", false, "accept Konnektor certificates without the C.SAK.AUT policy (test PKIs only)")
	flag.Parse()

	cfg, err := config(*eccCert, *eccKey, *rsaCert, *rsaKey, *cas, *paired, *anyPolicy, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %v", ln.Addr())
	log.Fatal(serve(ln, cfg, log.Printf))
}

// config builds the server configuration from the flag values.
func config(eccCert, eccKey, rsaCert, rsaKey, caFiles, paired string, anyPolicy bool, logf func(string, ...any)) (*tls.Config, error) {
	s := &ti.KTServer{}
	if eccCert != "" {
		c, err := tlsutil.LoadX509KeyPair(eccCert, eccKey)
		if err != nil {
			return nil, fmt.Errorf("ECC identity: %w", err)
		}
		s.ECC = &c
	}
	if rsaCert != "" {
		c, err := tls.LoadX509KeyPair(rsaCert, rsaKey)
		if err != nil {
			return nil, fmt.Errorf("RSA identity: %w", err)
		}
		s.RSA = &c
	}
	var cas []*x509.Certificate
	for _, f := range strings.Split(caFiles, ",") {
		if f == "" {
			continue
		}
		c, err := readCerts(f)
		if err != nil {
			return nil, err
		}
		cas = append(cas, c...)
	}
	if len(cas) == 0 {
		return nil, errors.New("no Konnektor CA certificates (-konnektor-ca)")
	}
	s.Konnektor = ti.KonnektorVerifier(cas)
	if anyPolicy {
		s.Konnektor.Policies = nil
	}
	pairs := map[string]bool{}
	for _, h := range strings.Split(paired, ",") {
		if h != "" {
			pairs[strings.ToLower(h)] = true
		}
	}
	s.Paired = func(spki []byte) bool {
		sum := sha256.Sum256(spki)
		return pairs[hex.EncodeToString(sum[:])]
	}
	s.OnState = func(state ti.State, cs tls.ConnectionState, reason error) {
		peer := "no client certificate"
		if len(cs.PeerCertificates) > 0 {
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			peer = fmt.Sprintf("client %q, SPKI SHA-256 %x", cs.PeerCertificates[0].Subject, sum)
		}
		if reason != nil {
			logf("%v (%s): %v", state, peer, reason)
		} else {
			logf("%v (%s)", state, peer)
		}
	}
	return s.Config()
}

func readCerts(file string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificates", file)
	}
	return certs, nil
}

// serve accepts connections on ln. For each, it completes the handshake,
// logs the negotiated parameters, and echoes lines until the client closes
// the connection or fails, for example by renegotiating.
func serve(ln net.Listener, cfg *tls.Config, logf func(string, ...any)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			tc := tls.Server(c, cfg)
			if err := tc.Handshake(); err != nil {
				logf("handshake with %v failed: %v", c.RemoteAddr(), err)
				return
			}
			cs := tc.ConnectionState()
			logf("handshake with %v: %s, group %v, server certificate %s",
				c.RemoteAddr(), tls.CipherSuiteName(cs.CipherSuite), cs.CurveID, identityName(cs))
			r := bufio.NewScanner(tc)
			for r.Scan() {
				fmt.Fprintf(tc, "KT: %s\n", r.Text())
			}
			if err := r.Err(); err != nil {
				logf("connection with %v ended: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

func identityName(cs tls.ConnectionState) string {
	if cs.CipherSuite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || cs.CipherSuite == tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
		return "RSA"
	}
	return "ECC"
}
