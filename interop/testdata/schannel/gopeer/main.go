//go:build ivory

// Command gopeer is the Go side of the Windows SChannel interop tests
// (interop/testdata/schannel): a TLS server or client with a Brainpool
// identity that requires a certificate from the peer, offers only the
// Brainpool groups, and prints what was negotiated as one JSON line. It
// exits with status 1 if the handshake or the exchange of one line fails.
//
// It is cross-compiled for Windows with the overlay:
//
//	GOOS=windows go build -o gopeer.exe ./interop/testdata/schannel/gopeer
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// result is printed as JSON after the handshake.
type result struct {
	Role    string `json:"role"`
	Version string `json:"version"`
	Suite   string `json:"suite"`
	Group   uint16 `json:"group"`
	PeerCN  string `json:"peer_cn"`
	// PeerSchemes are the signature schemes of the peer's signatures
	// that VerifyUnsupportedSignature checked.
	PeerSchemes []uint16 `json:"peer_schemes"`
	// HelloGroups and HelloSchemes are what the client offered (server
	// only).
	HelloGroups   []uint16 `json:"hello_groups,omitempty"`
	HelloSchemes  []uint16 `json:"hello_schemes,omitempty"`
	HelloVersions []uint16 `json:"hello_versions,omitempty"`
	// Fallback reports whether tlsutil.TLS12Fallback chose TLS 1.2.
	Fallback bool   `json:"fallback,omitempty"`
	Error    string `json:"error,omitempty"`
}

func main() {
	role := flag.String("role", "server", "server or client")
	addr := flag.String("addr", "127.0.0.1:4433", "address to listen on or connect to")
	version := flag.String("version", "1.2", "TLS version: 1.2, 1.3, or 1.2-1.3 for both")
	certFile := flag.String("cert", "", "certificate (PEM)")
	keyFile := flag.String("key", "", "private key (PEM)")
	caFile := flag.String("ca", "", "CA certificate that issued the peer's certificate (PEM)")
	serverName := flag.String("servername", "localhost", "client: expected server name")
	timeout := flag.Duration("timeout", 60*time.Second, "how long to wait")
	legacy := flag.Bool("tls13-legacy-groups", false, "also use the TLS 1.2 Brainpool groups 26-28 in TLS 1.3, as SChannel does (not RFC 8734; experiments only)")
	fallback := flag.Bool("tls12-fallback", false, "server: answer SChannel-style TLS 1.3 clients in TLS 1.2 (tlsutil.TLS12Fallback)")
	flag.Parse()

	r := &result{Role: *role}
	err := run(r, *role, *addr, *version, *certFile, *keyFile, *caFile, *serverName, *timeout, *legacy, *fallback)
	if err != nil {
		r.Error = err.Error()
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if err != nil {
		os.Exit(1)
	}
}

func run(r *result, role, addr, version, certFile, keyFile, caFile, serverName string, timeout time.Duration, legacy, fallback bool) error {
	cert, err := tlsutil.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ca, err := readCert(caFile)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	verify := func(leaf *x509.Certificate, scheme tls.SignatureScheme, signed, sig []byte) error {
		mu.Lock()
		r.PeerSchemes = append(r.PeerSchemes, uint16(scheme))
		mu.Unlock()
		return tlsutil.VerifyUnsupportedSignature(leaf, scheme, signed, sig)
	}
	curves := []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()}
	c := &tls.Config{
		Certificates:               []tls.Certificate{cert},
		KeyExchanges:               tlsutil.KeyExchanges(curves...),
		VerifyUnsupportedSignature: verify,
		SignatureSchemes:           tlsutil.SignatureSchemes(),
	}
	if legacy {
		for _, ke := range tlsutil.KeyExchanges(curves...) {
			if ke.MaxVersion == tls.VersionTLS12 {
				ke.MinVersion, ke.MaxVersion = tls.VersionTLS13, 0
				c.KeyExchanges = append(c.KeyExchanges, ke)
			}
		}
	}
	// Only the Brainpool groups: 26-28 in TLS 1.2, 31-33 in TLS 1.3.
	for _, ke := range c.KeyExchanges {
		if !slices.Contains(c.CurvePreferences, ke.ID) {
			c.CurvePreferences = append(c.CurvePreferences, ke.ID)
		}
	}
	switch version {
	case "1.2":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	case "1.3":
		c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	case "1.2-1.3":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
	default:
		return fmt.Errorf("unknown version %q", version)
	}
	usage := x509.ExtKeyUsageClientAuth
	if role == "client" {
		usage = x509.ExtKeyUsageServerAuth
	}
	c.VerifyConnection = (&tlsutil.ChainVerifier{Roots: []*x509.Certificate{ca}, KeyUsage: usage}).VerifyConnection

	var conn *tls.Conn
	switch role {
	case "server":
		c.ClientAuth = tls.RequireAnyClientCert
		var next func(*tls.ClientHelloInfo) (*tls.Config, error)
		if fallback {
			next = tlsutil.TLS12Fallback(c, nil)
		}
		c.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			for _, g := range chi.SupportedCurves {
				r.HelloGroups = append(r.HelloGroups, uint16(g))
			}
			for _, s := range chi.SignatureSchemes {
				r.HelloSchemes = append(r.HelloSchemes, uint16(s))
			}
			r.HelloVersions = slices.Clone(chi.SupportedVersions)
			if next == nil {
				return nil, nil
			}
			config, err := next(chi)
			r.Fallback = config != nil
			return config, err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		defer ln.Close()
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(os.Stderr, "gopeer: listening on %s\n", ln.Addr())
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		conn = tls.Server(raw, c)
	case "client":
		c.ServerName = serverName
		c.InsecureSkipVerify = true // verified by the ChainVerifier
		raw, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return err
		}
		conn = tls.Client(raw, c)
	default:
		return fmt.Errorf("unknown role %q", role)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return err
	}
	cs := conn.ConnectionState()
	r.Version = tls.VersionName(cs.Version)
	r.Suite = tls.CipherSuiteName(cs.CipherSuite)
	r.Group = uint16(cs.CurveID)
	if len(cs.PeerCertificates) > 0 {
		r.PeerCN = cs.PeerCertificates[0].Subject.CommonName
	}
	// One line each way.
	br := bufio.NewReader(conn)
	if role == "client" {
		if _, err := fmt.Fprintf(conn, "hello from ivory\n"); err != nil {
			return err
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "hello from schannel") {
			return fmt.Errorf("unexpected reply %q", line)
		}
		return nil
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "hello from schannel") {
		return fmt.Errorf("unexpected message %q", line)
	}
	_, err = fmt.Fprintf(conn, "hello from ivory\n")
	return err
}

func readCert(name string) (*x509.Certificate, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data", name)
	}
	return x509.ParseCertificate(block.Bytes)
}
