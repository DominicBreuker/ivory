//go:build ivory

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const pki = "../../testdata/pki"

func pkiFile(name string) string { return filepath.Join(pki, name) }

// logs collects the server's log lines.
type logs struct {
	mu    sync.Mutex
	lines []string
	added chan struct{}
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
	select {
	case l.added <- struct{}{}:
	default:
	}
}

// wait returns the first line that contains want, or fails after a timeout.
func (l *logs) wait(t *testing.T, want string) string {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		l.mu.Lock()
		for _, line := range l.lines {
			if strings.Contains(line, want) {
				l.mu.Unlock()
				return line
			}
		}
		l.mu.Unlock()
		select {
		case <-l.added:
		case <-deadline:
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("no log line with %q; log:\n%s", want, strings.Join(l.lines, "\n"))
			return ""
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startServer runs the example server on a local port with the test PKI;
// pairedSPKIOf names a certificate whose key is paired.
func startServer(t *testing.T, pairedSPKIOf string) (string, *logs) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	l := &logs{added: make(chan struct{}, 1)}
	paired := ""
	if pairedSPKIOf != "" {
		c, err := readCerts(pkiFile(pairedSPKIOf + ".pem"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(c[0].RawSubjectPublicKeyInfo)
		paired = hex.EncodeToString(sum[:])
	}
	cfg, err := config(pkiFile("bp256-server.pem"), pkiFile("bp256-server.key"),
		pkiFile("rsa-server.pem"), pkiFile("rsa-server.key"), pkiFile("bp256-ca.pem"), paired, true, l.logf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serve(ln, cfg, l.logf)
	return ln.Addr().String(), l
}

// sClient runs openssl s_client against addr, sends lines, and returns its
// output once the server answered the last line or the server log shows
// waitLog.
func sClient(t *testing.T, addr string, l *logs, waitLog string, lines []string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Konnektors offer the Brainpool groups (A_17094-02); without them,
	// the terminal presents its RSA identity.
	base := []string{"s_client", "-connect", addr, "-tls1_2", "-msg"}
	if !slices.Contains(args, "-groups") {
		base = append(base, "-groups", "P-256:P-384:brainpoolP256r1:brainpoolP384r1")
	}
	cmd := exec.CommandContext(ctx, "openssl", append(base, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	l.wait(t, "handshake with")
	for _, line := range lines {
		io.WriteString(stdin, line+"\n")
		time.Sleep(300 * time.Millisecond)
	}
	if waitLog != "" {
		l.wait(t, waitLog)
	}
	stdin.Close()
	cmd.Wait()
	return out.String()
}

func TestKTServer(t *testing.T) {
	for _, tt := range []struct {
		name      string
		paired    string
		args      []string
		wantState string
		wantOut   []string
	}{
		{
			name:      "Brainpool client certificate, ECDSA suites only: ECC identity",
			args:      []string{"-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256", "-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error", "-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")},
			wantState: "State_ClientWithoutPairing (client \"CN=ivory Brainpool P256 Client\"",
			wantOut:   []string{"Verification: OK", "KT: ping", "Cipher is ECDHE-ECDSA-AES128-GCM-SHA256"},
		},
		{
			name:      "paired Konnektor",
			paired:    "bp256-client",
			args:      []string{"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error", "-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")},
			wantState: "State_ClientWithPairing",
			wantOut:   []string{"Verification: OK", "KT: ping"},
		},
		{
			name:      "RSA suites only: RSA identity",
			args:      []string{"-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-CAfile", pkiFile("rsa-ca.pem"), "-verify_return_error", "-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key")},
			wantState: "State_ClientWithoutPairing",
			wantOut:   []string{"Verification: OK", "KT: ping", "Cipher is ECDHE-RSA-AES128-GCM-SHA256"},
		},
		{
			name:      "no Brainpool group offered: RSA identity",
			args:      []string{"-groups", "P-256:P-384", "-CAfile", pkiFile("rsa-ca.pem"), "-verify_return_error"},
			wantState: "State_InvalidClient (no client certificate)",
			wantOut:   []string{"Verification: OK", "KT: ping", "Cipher is ECDHE-RSA"},
		},
		{
			name:      "no client certificate (A_22890)",
			args:      []string{"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error"},
			wantState: "State_InvalidClient (no client certificate)",
			wantOut:   []string{"Verification: OK", "KT: ping"},
		},
		{
			name:      "client certificate from another CA",
			args:      []string{"-CAfile", pkiFile("bp256-ca.pem"), "-verify_return_error", "-cert", pkiFile("bp384-client.pem"), "-key", pkiFile("bp384-client.key")},
			wantState: "State_InvalidClient (client \"CN=ivory Brainpool P384 Client\"",
			wantOut:   []string{"Verification: OK", "KT: ping"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addr, l := startServer(t, tt.paired)
			out := sClient(t, addr, l, "", []string{"ping"}, tt.args...)
			l.wait(t, tt.wantState)
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("s_client output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestKTServerRenegotiation checks that the terminal refuses a
// renegotiation with a fatal no_renegotiation alert (GS-A_5524, P0).
func TestKTServerRenegotiation(t *testing.T) {
	addr, l := startServer(t, "")
	out := sClient(t, addr, l, "connection with", []string{"hello", "R"},
		"-CAfile", pkiFile("bp256-ca.pem"), "-cert", pkiFile("bp256-client.pem"), "-key", pkiFile("bp256-client.key"))
	line := l.wait(t, "connection with")
	if !strings.Contains(line, "no renegotiation") {
		t.Errorf("server log %q, want a no renegotiation error", line)
	}
	if !strings.Contains(out, "RENEGOTIATING") || !strings.Contains(out, "fatal no_renegotiation") {
		t.Errorf("s_client output lacks the renegotiation or the alert:\n%s", out)
	}
}
