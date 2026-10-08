//go:build ivory

// Command connectorclient is an example Konnektor-like TLS client, built
// with package ti: it connects to a TLS server such as an eHealth-KT with a
// Brainpool client certificate, offers the ECDSA suites first (with the
// ivory overlay profile kt) and the groups P-256, P-384, brainpoolP256r1
// and brainpoolP384r1 (A_17094-02), and checks the server certificate
// against stored CA certificates in two levels.
//
// Usage, with the test PKI of this repository:
//
//	connectorclient -addr 127.0.0.1:4742 \
//		-cert testdata/pki/bp256-client.pem -key testdata/pki/bp256-client.key \
//		-ca testdata/pki/bp256-ca.pem -any-policy
//
// -any-policy skips the C.SMKT.AUT policy check: the test PKI has no TI
// policies.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4742", "server `address`")
	certFile := flag.String("cert", "", "Brainpool client certificate (PEM)")
	keyFile := flag.String("key", "", "Brainpool client key (PEM, PKCS #8 or SEC 1)")
	caFiles := flag.String("ca", "", "comma-separated PEM files with the CA certificates of the server's certificate")
	anyPolicy := flag.Bool("any-policy", false, "accept server certificates without the C.SMKT.AUT policy (test PKIs only)")
	message := flag.String("message", "hello from the Konnektor", "line to send")
	flag.Parse()

	cfg, err := config(*certFile, *keyFile, *caFiles, *anyPolicy)
	if err != nil {
		log.Fatal(err)
	}
	cs, reply, err := run(*addr, cfg, *message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s, group %v, server %q\n%s\n", tls.CipherSuiteName(cs.CipherSuite), cs.CurveID, cs.PeerCertificates[0].Subject, reply)
}

func config(certFile, keyFile, caFiles string, anyPolicy bool) (*tls.Config, error) {
	cert, err := tlsutil.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	var cas []*x509.Certificate
	for _, f := range strings.Split(caFiles, ",") {
		if f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for {
			var block *pem.Block
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			cas = append(cas, c)
		}
	}
	if len(cas) == 0 {
		return nil, fmt.Errorf("no CA certificates (-ca)")
	}
	kt := &ti.Verifier{CAs: cas, Policies: []x509.OID{ti.PolicySMKTAUT}}
	if anyPolicy {
		kt.Policies = nil
	}
	return ti.ConnectorClientConfig(cert, kt), nil
}

// run connects to addr, sends message as a line and returns the
// connection state and the first line of the reply.
func run(addr string, cfg *tls.Config, message string) (tls.ConnectionState, string, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(c, message); err != nil {
		return tls.ConnectionState{}, "", err
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return tls.ConnectionState{}, "", err
	}
	return c.ConnectionState(), strings.TrimSpace(reply), nil
}
