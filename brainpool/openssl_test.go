package brainpool_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

const pki = "../testdata/pki"

func openssl(t *testing.T, args ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	cmd := exec.Command("openssl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, stderr.Bytes())
	}
	return out
}

func readKey(t *testing.T, name string) *brainpool.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pki, name))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	k, err := x509util.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*brainpool.PrivateKey)
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOpenSSLSignatures signs with OpenSSL and verifies here, and the
// reverse, for each curve and several hashes, with the test PKI's keys
// and with fresh keys.
func TestOpenSSLSignatures(t *testing.T) {
	dir := t.TempDir()
	msg := []byte("ivory brainpool and OpenSSL")
	msgFile := filepath.Join(dir, "msg")
	if err := os.WriteFile(msgFile, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	type keyCase struct {
		name string
		key  *brainpool.PrivateKey
	}
	var keys []keyCase
	for _, n := range []string{"bp256-server.key", "bp384-server.key", "bp512-server.key"} {
		keys = append(keys, keyCase{n, readKey(t, n)})
	}
	for _, tt := range curves {
		k, _ := brainpool.GenerateKey(tt.c)
		keys = append(keys, keyCase{"fresh " + tt.c.String(), k})
	}
	for i, kc := range keys {
		t.Run(kc.name, func(t *testing.T) {
			p8, err := x509util.MarshalPKCS8PrivateKey(kc.key)
			if err != nil {
				t.Fatal(err)
			}
			keyFile := writePEM(t, dir, "key"+string(rune('a'+i)), "PRIVATE KEY", p8)
			spki, _ := x509util.MarshalPKIXPublicKey(kc.key.PublicKey())
			pubFile := writePEM(t, dir, "pub"+string(rune('a'+i)), "PUBLIC KEY", spki)
			// OpenSSL derives the same public key.
			if got := openssl(t, "pkey", "-in", keyFile, "-pubout", "-outform", "DER"); !bytes.Equal(got, spki) {
				t.Error("OpenSSL derives another public key")
			}
			for _, h := range []struct {
				hash crypto.Hash
				flag string
			}{{crypto.SHA256, "-sha256"}, {crypto.SHA384, "-sha384"}, {crypto.SHA512, "-sha512"}} {
				d := digest(h.hash, msg)
				// OpenSSL signs, we verify.
				sig := openssl(t, "dgst", h.flag, "-sign", keyFile, msgFile)
				if !brainpool.VerifyASN1(kc.key.PublicKey(), d, sig) {
					t.Errorf("%v: OpenSSL's signature rejected", h.hash)
				}
				// We sign, OpenSSL verifies.
				ours, err := kc.key.Sign(rand.Reader, d, h.hash)
				if err != nil {
					t.Fatal(err)
				}
				sigFile := filepath.Join(dir, "sig")
				if err := os.WriteFile(sigFile, ours, 0o600); err != nil {
					t.Fatal(err)
				}
				out := openssl(t, "dgst", h.flag, "-verify", pubFile, "-signature", sigFile, msgFile)
				if !bytes.Contains(out, []byte("Verified OK")) {
					t.Errorf("%v: OpenSSL: %s", h.hash, out)
				}
			}
		})
	}
}

// TestOpenSSLECDH compares ECDH with openssl pkeyutl -derive.
func TestOpenSSLECDH(t *testing.T) {
	dir := t.TempDir()
	for _, pair := range [][2]string{
		{"bp256-server", "bp256-client"},
		{"bp384-server", "bp384-client"},
		{"bp512-server", "bp512-client"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			a := readKey(t, pair[0]+".key")
			b := readKey(t, pair[1]+".key")
			spki, _ := x509util.MarshalPKIXPublicKey(b.PublicKey())
			peer := writePEM(t, dir, pair[1]+".pub", "PUBLIC KEY", spki)
			want := openssl(t, "pkeyutl", "-derive", "-inkey", filepath.Join(pki, pair[0]+".key"), "-peerkey", peer)
			got, err := a.ECDH(b.PublicKey())
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("ECDH = %x, %v; OpenSSL %x", got, err, want)
			}
		})
	}
}
