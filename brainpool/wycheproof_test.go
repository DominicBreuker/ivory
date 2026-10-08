package brainpool_test

import (
	"bufio"
	"crypto"
	"crypto/sha256"
	_ "crypto/sha3" // registers crypto.SHA3_*
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
)

const wycheproofDir = "testdata/wycheproof"

// TestWycheproofPinned checks the vendored files against SHA256SUMS.
func TestWycheproofPinned(t *testing.T) {
	f, err := os.Open(filepath.Join(wycheproofDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("bad line %q", sc.Text())
		}
		b, err := os.ReadFile(filepath.Join(wycheproofDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != sum {
			t.Errorf("%s: SHA-256 %s, want %s", name, got, sum)
		}
		seen++
	}
	if seen != 12 {
		t.Errorf("%d files in SHA256SUMS, want 12", seen)
	}
}

type wycheproofFile[G any] struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []G    `json:"testGroups"`
}

type wycheproofTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Result  string   `json:"result"` // valid, invalid or acceptable
}

type ecdsaGroup struct {
	Type      string `json:"type"` // EcdsaVerify or EcdsaP1363Verify
	PublicKey struct {
		Curve        string `json:"curve"`
		Uncompressed string `json:"uncompressed"`
	} `json:"publicKey"`
	PublicKeyDer string `json:"publicKeyDer"`
	SHA          string `json:"sha"`
	Tests        []struct {
		wycheproofTest
		Msg string `json:"msg"`
		Sig string `json:"sig"`
	} `json:"tests"`
}

func readWycheproof[G any](t *testing.T, name string) *wycheproofFile[G] {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(wycheproofDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var f wycheproofFile[G]
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func curveByName(t *testing.T, name string) brainpool.Curve {
	t.Helper()
	for _, tt := range curves {
		if tt.c.String() == name {
			return tt.c
		}
	}
	t.Fatalf("unknown curve %q", name)
	return nil
}

func hashByName(t *testing.T, name string) crypto.Hash {
	t.Helper()
	h, ok := map[string]crypto.Hash{
		"SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384, "SHA-512": crypto.SHA512,
		"SHA3-256": crypto.SHA3_256, "SHA3-384": crypto.SHA3_384, "SHA3-512": crypto.SHA3_512,
	}[name]
	if !ok {
		t.Fatalf("unknown hash %q", name)
	}
	return h
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWycheproofECDSA runs all ECDSA verification vectors: valid
// signatures must verify, invalid ones must not. The files have no
// "acceptable" cases.
func TestWycheproofECDSA(t *testing.T) {
	for _, name := range []string{
		"ecdsa_brainpoolP256r1_sha256_test.json",
		"ecdsa_brainpoolP256r1_sha3_256_test.json",
		"ecdsa_brainpoolP256r1_sha256_p1363_test.json",
		"ecdsa_brainpoolP384r1_sha384_test.json",
		"ecdsa_brainpoolP384r1_sha3_384_test.json",
		"ecdsa_brainpoolP384r1_sha384_p1363_test.json",
		"ecdsa_brainpoolP512r1_sha512_test.json",
		"ecdsa_brainpoolP512r1_sha3_512_test.json",
		"ecdsa_brainpoolP512r1_sha512_p1363_test.json",
	} {
		t.Run(name, func(t *testing.T) {
			f := readWycheproof[ecdsaGroup](t, name)
			var counts = map[string]int{}
			for _, g := range f.TestGroups {
				c := curveByName(t, g.PublicKey.Curve)
				pub, err := brainpool.NewPublicKey(c, mustDecodeHex(t, g.PublicKey.Uncompressed))
				if err != nil {
					t.Fatalf("group public key: %v", err)
				}
				h := hashByName(t, g.SHA)
				for _, tc := range g.Tests {
					hh := h.New()
					hh.Write(mustDecodeHex(t, tc.Msg))
					d := hh.Sum(nil)
					sig := mustDecodeHex(t, tc.Sig)
					var got bool
					switch g.Type {
					case "EcdsaVerify":
						got = brainpool.VerifyASN1(pub, d, sig)
					case "EcdsaP1363Verify":
						got = brainpool.VerifyRaw(pub, d, sig)
					default:
						t.Fatalf("unknown group type %q", g.Type)
					}
					switch tc.Result {
					case "valid":
						if !got {
							t.Errorf("tcId %d (%s, %v): valid signature rejected", tc.TcID, tc.Comment, tc.Flags)
						}
					case "invalid":
						if got {
							t.Errorf("tcId %d (%s, %v): invalid signature accepted", tc.TcID, tc.Comment, tc.Flags)
						}
					default:
						t.Errorf("tcId %d: unexpected result %q", tc.TcID, tc.Result)
					}
					counts[tc.Result]++
				}
			}
			if total := counts["valid"] + counts["invalid"]; total != f.NumberOfTests {
				t.Errorf("ran %d tests, file has %d", total, f.NumberOfTests)
			}
			t.Logf("%d valid, %d invalid", counts["valid"], counts["invalid"])
		})
	}
}
