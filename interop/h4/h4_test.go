//go:build ivory

// Package h4 tests what a TLS 1.2 server needs without patch P4: a Go server with a Brainpool identity
// that requires a Brainpool client certificate, built without patch P4
// (so without Config.KeyExchanges), against an OpenSSL client. It uses no
// API of P4, so it builds with an overlay of P0-P2 or P0-P3 as well as
// with the full overlay. It runs with P0-P3: the server signs with a
// *brainpool.PrivateKey, which needs P3 (P3 adds no API).
package h4

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

const pki = "../../testdata/pki"

func readPEM(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pki, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readPEM(t, name))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verifySignature is a minimal Config.VerifyUnsupportedSignature for
// Brainpool keys and the TLS 1.2 ECDSA schemes.
func verifySignature(leaf *x509.Certificate, scheme tls.SignatureScheme, signed, sig []byte) error {
	k, err := x509util.ParsePKIXPublicKey(leaf.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}
	pub, ok := k.(*brainpool.PublicKey)
	if !ok {
		return errors.New("not a Brainpool key")
	}
	h := map[tls.SignatureScheme]crypto.Hash{
		tls.ECDSAWithP256AndSHA256: crypto.SHA256,
		tls.ECDSAWithP384AndSHA384: crypto.SHA384,
		tls.ECDSAWithP521AndSHA512: crypto.SHA512,
	}[scheme]
	if h == 0 {
		return errors.New("unsupported signature scheme")
	}
	hh := h.New()
	hh.Write(signed)
	if !brainpool.VerifyASN1(pub, hh.Sum(nil), sig) {
		return errors.New("ECDSA verification failure")
	}
	return nil
}

func readKey(t *testing.T, name string) *brainpool.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(readPEM(t, name))
	k, err := x509util.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*brainpool.PrivateKey)
}

func serverConfig(t *testing.T) *tls.Config {
	leaf := parseCert(t, "bp256-server.pem")
	key := readKey(t, "bp256-server.key")
	ca := parseCert(t, "bp256-ca.pem")
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		// An opaque key for crypto/tls (P3): it signs with the listed
		// TLS 1.2 ECDSA schemes.
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}},
		ClientAuth:                 tls.RequireAnyClientCert,
		VerifyUnsupportedSignature: verifySignature,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return x509util.CheckCertificateSignatureFrom(cs.PeerCertificates[0], ca)
		},
	}
}

// run serves one connection with config to openssl s_client offering
// groups. It returns the server's connection state, s_client's output,
// and the server's handshake error.
func run(t *testing.T, config *tls.Config, groups string) (tls.ConnectionState, string, error) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", "s_client", "-connect", ln.Addr().String(),
		"-tls1_2", "-groups", groups,
		"-CAfile", filepath.Join(pki, "bp256-ca.pem"), "-verify_return_error",
		"-cert", filepath.Join(pki, "bp256-client.pem"), "-key", filepath.Join(pki, "bp256-client.key"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	c := tls.Server(conn, config)
	herr := c.Handshake()
	if herr == nil {
		// s_client exits when its stdin closes; wait until it has seen
		// the end of the handshake by sending data and reading its
		// close_notify.
		io.WriteString(c, "hello from H4\n")
		stdin.Close()
		io.Copy(io.Discard, c)
	} else {
		stdin.Close()
	}
	conn.Close()
	cmd.Wait()
	t.Logf("openssl s_client -groups %s:\n%s", groups, out.String())
	return c.ConnectionState(), out.String(), herr
}

// TestH4: with P-256 offered next to brainpoolP256r1, the
// server needs no Brainpool group: it negotiates ECDHE with P-256 and
// authenticates both sides with Brainpool keys.
func TestH4(t *testing.T) {
	cs, out, err := run(t, serverConfig(t), "P-256:brainpoolP256r1")
	if err != nil {
		t.Fatal(err)
	}
	if cs.CurveID != tls.CurveP256 || cs.Version != tls.VersionTLS12 {
		t.Errorf("group, version = %v, %x; want P-256, TLS 1.2", cs.CurveID, cs.Version)
	}
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != "ivory Brainpool P256 Client" {
		t.Error("no Brainpool client certificate")
	}
	for _, want := range []string{"Server Temp Key: ECDH, prime256v1", "Verification: OK", "hello from H4"} {
		if !strings.Contains(out, want) {
			t.Errorf("s_client output lacks %q", want)
		}
	}
}

// TestH4BrainpoolOnly is the limit of TestH4: a client that offers only
// brainpoolP256r1 has no group in common with a server without P4.
func TestH4BrainpoolOnly(t *testing.T) {
	_, _, err := run(t, serverConfig(t), "brainpoolP256r1")
	if err == nil {
		t.Fatal("handshake succeeded without a common group")
	}
	t.Logf("server error: %v", err)
}
