//go:build ivory

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/tlsutil"
)

const pki = "../../testdata/pki"

func pkiFile(name string) string { return filepath.Join(pki, name) }

// freePort returns a local address that was free a moment ago.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestConnectorClient connects the example client to openssl s_server,
// which requires a client certificate from the Brainpool CA.
func TestConnectorClient(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	for _, tt := range []struct {
		groups    string
		wantGroup tls.CurveID
	}{
		{"P-256:brainpoolP256r1", tls.CurveP256},
		{"brainpoolP256r1", tlsutil.CurveBrainpoolP256r1},
	} {
		t.Run(tt.groups, func(t *testing.T) {
			addr := freePort(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			// -rev echoes each line reversed.
			cmd := exec.CommandContext(ctx, "openssl", "s_server", "-accept", addr, "-naccept", "1", "-rev",
				"-tls1_2", "-groups", tt.groups,
				"-cert", pkiFile("bp256-server.pem"), "-key", pkiFile("bp256-server.key"),
				"-Verify", "1", "-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error")
			stdin, _ := cmd.StdinPipe()
			defer stdin.Close()
			out, _ := cmd.StdoutPipe()
			cmd.Stderr = cmd.Stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewScanner(out)
			for lines.Scan() && !strings.Contains(lines.Text(), "ACCEPT") {
			}
			go io.Copy(io.Discard, out)

			cfg, err := config(pkiFile("bp256-client.pem"), pkiFile("bp256-client.key"), pkiFile("bp256-ca.pem"), true)
			if err != nil {
				t.Fatal(err)
			}
			cs, reply, err := run(addr, cfg, "olleh")
			if err != nil {
				t.Fatal(err)
			}
			if reply != "hello" {
				t.Errorf("reply = %q, want %q", reply, "hello")
			}
			if cs.CurveID != tt.wantGroup {
				t.Errorf("group = %v, want %v", cs.CurveID, tt.wantGroup)
			}
			if cs.Version != tls.VersionTLS12 || cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
				t.Errorf("version %x, suite %v; want TLS 1.2 with an ECDHE_ECDSA suite", cs.Version, tls.CipherSuiteName(cs.CipherSuite))
			}
		})
	}
}
