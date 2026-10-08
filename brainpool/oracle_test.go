package brainpool

import (
	"bytes"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

// pythonDeterministic signs msg with Python cryptography's deterministic
// ECDSA (RFC 6979) and returns r || s in hex, each of the curve's size. It
// skips the test if Python or a cryptography version with
// deterministic_signing is missing.
func pythonDeterministic(t *testing.T, curveName, hashName string, d, msg []byte) string {
	t.Helper()
	const script = `
import sys
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
curve = {"brainpoolP256r1": ec.BrainpoolP256R1(), "brainpoolP384r1": ec.BrainpoolP384R1(),
         "brainpoolP512r1": ec.BrainpoolP512R1()}[sys.argv[1]]
h = getattr(hashes, sys.argv[2])()
d = bytes.fromhex(sys.argv[3])
key = ec.derive_private_key(int.from_bytes(d, "big"), curve)
try:
    sig = key.sign(bytes.fromhex(sys.argv[4]), ec.ECDSA(h, deterministic_signing=True))
except Exception as e:  # old cryptography (TypeError) or OpenSSL < 3.2
    print("SKIP", type(e).__name__, e)
    sys.exit(0)
r, s = utils.decode_dss_signature(sig)
print((r.to_bytes(len(d), "big") + s.to_bytes(len(d), "big")).hex())
`
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}
	cmd := exec.Command("python3", "-I", "-c", script, curveName, hashName, hex.EncodeToString(d), hex.EncodeToString(msg))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(stderr.String(), "No module named") {
			t.Skip("Python cryptography not installed")
		}
		t.Fatalf("python3: %v\n%s", err, stderr.Bytes())
	}
	res := strings.TrimSpace(string(out))
	if strings.HasPrefix(res, "SKIP") {
		t.Skipf("Python cryptography can't sign deterministically: %s", res)
	}
	return res
}
