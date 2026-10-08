package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The K2 and K4 expectations hold for stock Go 1.27.1 and every overlay
// profile. K1 and K3 depend on the profile: wantK1, wantK3ECDSA and
// wantK3RSA come from expect_kt_test.go (build tag ivory_kt, profile kt,
// patches P6 and P7) or expect_test.go (stock Go and profile core).

func TestK1CipherSuiteOrder(t *testing.T) {
	r, err := probeTLS12()
	if err != nil {
		t.Fatal(err)
	}
	want := wantK1
	if !slices.Equal(r.suites, want) {
		t.Errorf("cipher_suites = %s; want %s", show(suiteNames, r.suites), show(suiteNames, want))
	}
}

func TestK2TLS13CipherSuites(t *testing.T) {
	r, err := probeTLS13()
	if err != nil {
		t.Fatal(err)
	}
	// ChaCha20-Poly1305 is always offered, which BSI TR-02102-2 doesn't
	// allow: the reason TI products stay on TLS 1.2.
	want := []uint16{0x1301, 0x1302, 0x1303}
	if !slices.Equal(r.suites, want) {
		t.Errorf("cipher_suites = %s; want %s", show(suiteNames, r.suites), show(suiteNames, want))
	}
}

func TestK3CertificateTypes(t *testing.T) {
	r, err := probeTLS12()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.certTypes, wantK3ECDSA) {
		t.Errorf("certificate_types on an ECDHE_ECDSA suite = % x; want % x", r.certTypes, wantK3ECDSA)
	}
	if !bytes.Equal(r.certTypesRSA, wantK3RSA) {
		t.Errorf("certificate_types on an ECDHE_RSA suite = % x; want % x", r.certTypesRSA, wantK3RSA)
	}
}

func TestK4SupportedGroups(t *testing.T) {
	r, err := probeTLS12()
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{0x0017, 0x0018}
	if !slices.Equal(r.groups, want) {
		t.Errorf("supported_groups = %s; want %s", show(groupNames, r.groups), show(groupNames, want))
	}
}

// syncBuffer is a bytes.Buffer that is safe for concurrent writes, for the
// output of a subprocess.
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

// TestK5Renegotiation lets openssl s_client renegotiate against a Go
// server and checks the alert it receives (GS-A_5524, overlay patch P0).
func TestK5Renegotiation(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	readData := make(chan struct{}, 1)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- renegServer(ln, func(format string, args ...any) {
			t.Logf(format, args...)
			select {
			case readData <- struct{}{}:
			default:
			}
		})
	}()

	// Canceling the context kills openssl if the test ends early.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, openssl, "s_client", "-connect", ln.Addr().String(), "-tls1_2", "-msg")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// s_client sends what it reads from stdin, and starts a renegotiation
	// when a read returns a line "R". Send data first and wait until the
	// server got it, so that the handshake is done and "R" is read alone.
	io.WriteString(stdin, "hello\n")
	select {
	case <-readData:
	case err := <-serverErr:
		t.Fatalf("server failed before the renegotiation: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for the server to read data")
	}
	io.WriteString(stdin, "R\n")
	select {
	case err = <-serverErr:
	case <-ctx.Done():
		t.Fatal("timeout waiting for the server to fail")
	}
	if err == nil || !strings.Contains(err.Error(), wantK5ServerError) {
		t.Errorf("server error = %v; want one containing %q", err, wantK5ServerError)
	}

	stdin.Close()
	cmd.Wait()
	t.Logf("openssl output:\n%s", out.String())
	if !strings.Contains(out.String(), "RENEGOTIATING") {
		t.Errorf("openssl did not renegotiate")
	}
	if !strings.Contains(out.String(), wantK5Alert) {
		t.Errorf("openssl did not receive %q", wantK5Alert)
	}
}
