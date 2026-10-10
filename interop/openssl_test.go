//go:build ivory

package interop

import (
	"bytes"
	"context"
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
	"sync"
	"testing"
	"time"
)

const (
	pki       = "../testdata/pki"
	greeting  = "hello from Go"
	opTimeout = 20 * time.Second
)

func pkiFile(name string) string { return filepath.Join(pki, name) }

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(pkiFile(name + ".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s: no PEM data", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// opensslBin is the openssl binary that startOpenSSL runs; see useOpenSSL3.
var opensslBin = "openssl"

func needOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(opensslBin); err != nil {
		t.Skip("openssl not found")
	}
}

// peerProc is a running peer: openssl s_server or s_client, or a
// BouncyCastle peer. Its stdin stays open until stop, because s_server and
// s_client exit when stdin closes.
type peerProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}

	mu  sync.Mutex
	out bytes.Buffer // stdout and stderr
}

type lockedWriter struct{ p *peerProc }

func (w lockedWriter) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return w.p.out.Write(b)
}

func startOpenSSL(t *testing.T, args ...string) *peerProc {
	t.Helper()
	needOpenSSL(t)
	return startPeer(t, opensslBin, args...)
}

// startPeer starts bin with args; the test's cleanup stops it and logs its
// output.
func startPeer(t *testing.T, bin string, args ...string) *peerProc {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	p := &peerProc{cmd: exec.CommandContext(ctx, bin, args...), done: make(chan struct{})}
	p.cmd.Stdout = lockedWriter{p}
	p.cmd.Stderr = lockedWriter{p}
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.stdin = stdin
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.cmd.Wait()
		cancel()
		close(p.done)
	}()
	t.Cleanup(func() {
		p.stop()
		t.Logf("%s %s:\n%s", bin, strings.Join(args, " "), p.output())
	})
	return p
}

func (p *peerProc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// waitFor waits until the output contains s or the process exits, and
// reports whether the output contains s.
func (p *peerProc) waitFor(s string) bool {
	return p.waitForN(s, 1)
}

// waitForN waits until the output contains s n times or the process
// exits, and reports whether it does.
func (p *peerProc) waitForN(s string, n int) bool {
	deadline := time.Now().Add(opTimeout)
	for time.Now().Before(deadline) {
		if strings.Count(p.output(), s) >= n {
			return true
		}
		select {
		case <-p.done:
			return strings.Count(p.output(), s) >= n
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

// stop closes stdin and waits for the process to exit; the context kills
// it after opTimeout. It returns the output.
func (p *peerProc) stop() string {
	p.stdin.Close()
	<-p.done
	return p.output()
}

// freeAddr returns a loopback address with a port that was free a moment
// ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// sServer starts openssl s_server for one connection and waits until it
// listens. It returns the process and its address.
func sServer(t *testing.T, args ...string) (*peerProc, string) {
	t.Helper()
	addr := freeAddr(t)
	p := startOpenSSL(t, append([]string{"s_server", "-accept", addr, "-naccept", "1"}, args...)...)
	if !p.waitFor("ACCEPT") {
		t.Fatalf("s_server didn't start:\n%s", p.output())
	}
	return p, addr
}

// goClient connects to addr with config. After a successful handshake it
// sends greeting.
func goClient(addr string, config *tls.Config) (tls.ConnectionState, error) {
	conn, err := net.DialTimeout("tcp", addr, opTimeout)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(opTimeout))
	c := tls.Client(conn, config)
	if err := c.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	if _, err := io.WriteString(c, greeting+"\n"); err != nil {
		return tls.ConnectionState{}, err
	}
	return c.ConnectionState(), nil
}

// clientWithSServer runs a Go client against openssl s_server. On success,
// it waits until s_server received the greeting.
func clientWithSServer(t *testing.T, config *tls.Config, sServerArgs ...string) (tls.ConnectionState, string, error) {
	t.Helper()
	p, addr := sServer(t, sServerArgs...)
	cs, err := goClient(addr, config)
	if err == nil && !p.waitFor(greeting) {
		err = errors.New("s_server didn't receive the greeting")
	}
	return cs, p.stop(), err
}

// serverWithSClient runs a Go server with config against openssl s_client.
// On success, the server sends the greeting and the function waits until
// s_client received it.
func serverWithSClient(t *testing.T, config *tls.Config, sClientArgs ...string) (tls.ConnectionState, string, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		cs   tls.ConnectionState
		err  error
		conn net.Conn
	}
	results := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		conn.SetDeadline(time.Now().Add(opTimeout))
		c := tls.Server(conn, config)
		if err := c.Handshake(); err != nil {
			results <- result{err: err, conn: conn}
			return
		}
		_, err = io.WriteString(c, greeting+"\n")
		results <- result{cs: c.ConnectionState(), err: err, conn: conn}
	}()
	p := startOpenSSL(t, append([]string{"s_client", "-connect", ln.Addr().String()}, sClientArgs...)...)
	var r result
	select {
	case r = <-results:
	case <-time.After(opTimeout):
		t.Fatal("timeout waiting for the Go server")
	}
	if r.conn != nil {
		defer r.conn.Close()
	}
	if r.err == nil && !p.waitFor(greeting) {
		r.err = errors.New("s_client didn't receive the greeting")
	}
	return r.cs, p.stop(), r.err
}

func curveName(id tls.CurveID) string {
	switch id {
	case 26:
		return "brainpoolP256r1"
	case 27:
		return "brainpoolP384r1"
	case 28:
		return "brainpoolP512r1"
	case 31:
		return "brainpoolP256r1tls13"
	case 32:
		return "brainpoolP384r1tls13"
	case 33:
		return "brainpoolP512r1tls13"
	}
	return id.String()
}
