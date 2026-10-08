package brainpool_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

type ecdhGroup struct {
	Type     string `json:"type"`
	Curve    string `json:"curve"`
	Encoding string `json:"encoding"` // asn: public keys are SubjectPublicKeyInfo
	Tests    []struct {
		wycheproofTest
		Public  string `json:"public"`
		Private string `json:"private"`
		Shared  string `json:"shared"`
	} `json:"tests"`
}

// TestWycheproofECDH runs the ECDH vectors with the peer key parsed by
// x509util.ParsePKIXPublicKey, as a TLS or CMS implementation would.
// "acceptable" cases (unusual but harmless encodings, such as compressed
// points or explicit curve parameters) may go either way; the test logs
// how many are accepted.
func TestWycheproofECDH(t *testing.T) {
	for _, name := range []string{
		"ecdh_brainpoolP256r1_test.json",
		"ecdh_brainpoolP384r1_test.json",
		"ecdh_brainpoolP512r1_test.json",
	} {
		t.Run(name, func(t *testing.T) {
			f := readWycheproof[ecdhGroup](t, name)
			counts := map[string]int{}
			for _, g := range f.TestGroups {
				if g.Type != "EcdhTest" || g.Encoding != "asn" {
					t.Fatalf("unexpected group %s/%s", g.Type, g.Encoding)
				}
				c := curveByName(t, g.Curve)
				size := brainpool.Size(c)
				for _, tc := range g.Tests {
					shared, err := wycheproofECDH(t, c, size, tc.Public, tc.Private)
					ok := err == nil
					if ok && !bytes.Equal(shared, mustDecodeHex(t, tc.Shared)) {
						t.Errorf("tcId %d (%s): shared secret %x, want %s", tc.TcID, tc.Comment, shared, tc.Shared)
					}
					switch tc.Result {
					case "valid":
						if !ok {
							t.Errorf("tcId %d (%s, %v): valid case failed: %v", tc.TcID, tc.Comment, tc.Flags, err)
						}
					case "invalid":
						if ok {
							t.Errorf("tcId %d (%s, %v): invalid case succeeded", tc.TcID, tc.Comment, tc.Flags)
						}
					case "acceptable":
					default:
						t.Errorf("tcId %d: unexpected result %q", tc.TcID, tc.Result)
					}
					key := tc.Result
					if tc.Result == "acceptable" {
						key += map[bool]string{true: " (accepted)", false: " (rejected)"}[ok]
					}
					counts[key]++
				}
			}
			total := 0
			for _, n := range counts {
				total += n
			}
			if total != f.NumberOfTests {
				t.Errorf("ran %d tests, file has %d", total, f.NumberOfTests)
			}
			t.Logf("%v", counts)
		})
	}
}

// wycheproofECDH parses the peer key and the private scalar and computes
// the shared secret. Private scalars are big-endian integers that may carry
// a leading zero byte.
func wycheproofECDH(t *testing.T, c brainpool.Curve, size int, public, private string) ([]byte, error) {
	t.Helper()
	pub, err := x509util.ParsePKIXPublicKey(mustDecodeHex(t, public))
	if err != nil {
		return nil, err
	}
	bp, ok := pub.(*brainpool.PublicKey)
	if !ok || bp.Curve() != c {
		return nil, errWrongCurve
	}
	d := mustDecodeHex(t, private)
	for len(d) > size && d[0] == 0 {
		d = d[1:]
	}
	scalar := make([]byte, size)
	copy(scalar[size-len(d):], d)
	k, err := brainpool.NewPrivateKey(c, scalar)
	if err != nil {
		t.Fatalf("private key %s: %v", private, err)
	}
	return k.ECDH(bp)
}

var errWrongCurve = errors.New("peer key is not on the expected Brainpool curve")
