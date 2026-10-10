package brainpool

// Known-answer tests from published sources: the ECDH test vectors of
// RFC 7027, Appendix A, which RFC 8734, Appendix A, repeats unchanged, and
// of RFC 6932, Appendix A; and the Brainpool vectors of Botan's tests for
// point multiplication and deterministic ECDSA (RFC 6979), vendored in
// testdata/botan.

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/sha1" // registers crypto.SHA1 for the Botan ECDSA vectors
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ecdhKAT is an ECDH test vector of the RFCs: the private keys dA and dB,
// the public keys (xA, yA) and (xB, yB), and the shared point (xZ, yZ),
// whose x-coordinate is the shared secret.
type ecdhKAT struct {
	src                            string
	curve                          *curve
	dA, xA, yA, dB, xB, yB, xZ, yZ string
}

// rfcECDH holds the vectors for the curves this package implements; RFC
// 6932 also has brainpoolP224r1.
var rfcECDH = []ecdhKAT{
	{
		src: "RFC 7027, Appendix A", curve: p256r1,
		dA: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
		xA: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
		yA: "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
		dB: "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
		xB: "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
		yB: "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
		xZ: "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
		yZ: "49C27868F4ECA2179BFD7D59B1E3BF34C1DBDE61AE12931648F43E59632504DE",
	},
	{
		src: "RFC 7027, Appendix A", curve: p384r1,
		dA: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
		xA: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
		yA: "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
		dB: "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
		xB: "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
		yB: "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
		xZ: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
		yZ: "0DF213417EBE4D8E40A5F76F66C56470C489A3478D146DECF6DF0D94BAE9E598157290F8756066975F1DB34B2324B7BD",
	},
	{
		src: "RFC 7027, Appendix A", curve: p512r1,
		dA: "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
		xA: "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD",
		yA: "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7",
		dB: "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429",
		xB: "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F",
		yB: "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA",
		xZ: "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F",
		yZ: "7DB71C3DEF63212841C463E881BDCF055523BD368240E6C3143BD8DEF8B3B3223B95E0F53082FF5E412F4222537A43DF1C6D25729DDB51620A832BE6A26680A2",
	},
	{
		src: "RFC 6932, Appendix A", curve: p256r1,
		dA: "041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",
		xA: "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
		yA: "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
		dB: "06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",
		xB: "8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",
		yB: "148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",
		xZ: "05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",
		yZ: "6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C",
	},
	{
		src: "RFC 6932, Appendix A", curve: p384r1,
		dA: "014EC0755B78594BA47FB0A56F6173045B4331E74BA1A6F47322E70D79D828D97E095884CA72B73FDABD5910DF0FA76A",
		xA: "45CB26E4384DAF6FB776885307B9A38B7AD1B5C692E0C32F0125332778F3B8D3F50CA358099B30DEB5EE69A95C058B4E",
		yA: "8173A1C54AFFA7E781D0E1E1D12C0DC2B74F4DF58E4A4E3AF7026C5D32DC530A2CD89C859BB4B4B768497F49AB8CC859",
		dB: "6B461CB79BD0EA519A87D6828815D8CE7CD9B3CAA0B5A8262CBCD550A015C90095B976F3529957506E1224A861711D54",
		xB: "01BF92A92EE4BE8DED1A911125C209B03F99E3161CFCC986DC7711383FC30AF9CE28CA3386D59E2C8D72CE1E7B4666E8",
		yB: "3289C4A3A4FEE035E39BDB885D509D224A142FF9FBCC5CFE5CCBB30268EE47487ED8044858D31D848F7A95C635A347AC",
		xZ: "04CC4FF3DCCCB07AF24E0ACC529955B36D7C807772B92FCBE48F3AFE9A2F370A1F98D3FA73FD0C0747C632E12F1423EC",
		yZ: "7F465F90BD69AFB8F828A214EB9716D66ABC59F17AF7C75EE7F1DE22AB5D05085F5A01A9382D05BF72D96698FE3FF64E",
	},
	{
		src: "RFC 6932, Appendix A", curve: p512r1,
		dA: "636B6BE0482A6C1C41AA7AE7B245E983392DB94CECEA2660A379CFE159559E357581825391175FC195D28BAC0CF03A7841A383B95C262B983782874CCE6FE333",
		xA: "0562E68B9AF7CBFD5565C6B16883B777FF11C199161ECC427A39D17EC2166499389571D6A994977C56AD8252658BA8A1B72AE42F4FB7532151AFC3EF0971CCDA",
		yA: "A7CA2D8191E21776A89860AFBC1F582FAA308D551C1DC6133AF9F9C3CAD59998D70079548140B90B1F311AFB378AA81F51B275B2BE6B7DEE978EFC7343EA642E",
		dB: "0AF4E7F6D52EDD52907BB8DBAB3992A0BB696EC10DF11892FF205B66D381ECE72314E6A6EA079CEA06961DBA5AE6422EF2E9EE803A1F236FB96A1799B86E5C8B",
		xB: "5A7954E32663DFF11AE24712D87419F26B708AC2B92877D6BFEE2BFC43714D89BBDB6D24D807BBD3AEB7F0C325F862E8BADE4F74636B97EAACE739E11720D323",
		yB: "96D14621A9283A1BED84DE8DD64836B2C0758B11441179DC0C54C0D49A47C03807D171DD544B72CAAEF7B7CE01C7753E2CAD1A861ECA55A71954EE1BA35E04BE",
		xZ: "1EE8321A4BBF93B9CF8921AB209850EC9B7066D1984EF08C2BB723236208AC8F1A483E79461A00E0D5F6921CE9D360502F85C812BEDEE23AC5B210E5811B191E",
		yZ: "2632095B7B936174B41FD2FAF369B1D18DCADEED7E410A7E251F0831097C50D02CFED02607B6A2D5ADB4C0006008562208631875B58B54ECDA5A4F9FE9EAABA6",
	},
}

func katHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// katScalar decodes a scalar and left-pads it to the curve's size.
func katScalar(t *testing.T, c *curve, s string) []byte {
	t.Helper()
	b := katHex(t, s)
	if len(b) > c.size {
		t.Fatalf("scalar %s is longer than %d bytes", s, c.size)
	}
	return append(make([]byte, c.size-len(b)), b...)
}

func TestRFCECDH(t *testing.T) {
	for _, v := range rfcECDH {
		c := v.curve
		t.Run(v.src+"/"+c.name, func(t *testing.T) {
			keys := make([]*PrivateKey, 2)
			for i, k := range [][3]string{{v.dA, v.xA, v.yA}, {v.dB, v.xB, v.yB}} {
				priv, err := NewPrivateKey(c, katHex(t, k[0]))
				if err != nil {
					t.Fatal(err)
				}
				want := append([]byte{4}, append(katHex(t, k[1]), katHex(t, k[2])...)...)
				if got := priv.PublicKey().Bytes(); !bytes.Equal(got, want) {
					t.Errorf("public key %d = %x, want %x", i, got, want)
				}
				keys[i] = priv
			}
			a, b := keys[0], keys[1]
			xZ := katHex(t, v.xZ)
			for _, tt := range []struct {
				name string
				priv *PrivateKey
				peer *PublicKey
			}{{"dA·QB", a, b.PublicKey()}, {"dB·QA", b, a.PublicKey()}} {
				shared, err := tt.priv.ECDH(tt.peer)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shared, xZ) {
					t.Errorf("ECDH %s = %x, want %x", tt.name, shared, xZ)
				}
				shared, err = tt.priv.Decapsulate(tt.peer.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shared, xZ) {
					t.Errorf("Decapsulate %s = %x, want %x", tt.name, shared, xZ)
				}
			}
			// The whole shared point, y included.
			x, y, ok := c.affine(c.scalarMult(b.PublicKey().q, a.Bytes()))
			if ok != 1 || !bytes.Equal(x, xZ) || !bytes.Equal(y, katHex(t, v.yZ)) {
				t.Errorf("dA·QB = (%x, %x), want (%s, %s)", x, y, v.xZ, v.yZ)
			}
		})
	}
}

const botanDir = "testdata/botan"

// botanCurves maps Botan's curve names to the curves of this package.
var botanCurves = map[string]*curve{
	"brainpool256r1": p256r1,
	"brainpool384r1": p384r1,
	"brainpool512r1": p512r1,
}

// TestBotanPinned checks the vendored files against SHA256SUMS.
func TestBotanPinned(t *testing.T) {
	sums, err := os.ReadFile(filepath.Join(botanDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		b, err := os.ReadFile(filepath.Join(botanDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != sum {
			t.Errorf("%s: SHA-256 %s, want %s", name, got, sum)
		}
		seen++
	}
	if seen != 3 {
		t.Errorf("%d files in SHA256SUMS, want 3", seen)
	}
}

// botanVectors returns the Brainpool vectors of a Botan test vector file.
// The file has "key = value" lines; a "[name]" line starts the section of
// a curve, and a "Group = name" line names the curve as well. A vector
// ends with the line that sets the key last; the other keys keep their
// values for the following vectors, as in Botan's test runner.
func botanVectors(t *testing.T, name, last string) []map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(botanDir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]string
	cur := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			cur = map[string]string{"Group": line[1 : len(line)-1]}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: bad line %q", name, line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		cur[key] = value
		if key != last {
			continue
		}
		if _, ok := botanCurves[cur["Group"]]; !ok {
			continue
		}
		v := make(map[string]string, len(cur))
		for k, x := range cur {
			v[k] = x
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// decodePoint decodes a compressed or uncompressed point with math/big
// (test code; the package itself only accepts uncompressed points).
func decodePoint(t *testing.T, c *curve, s string) *point {
	t.Helper()
	b := katHex(t, s)
	if len(b) == 1+2*c.size && b[0] == 4 {
		q, err := c.pointFromAffine(b[1:1+c.size], b[1+c.size:])
		if err != nil {
			t.Fatalf("point %s: %v", s, err)
		}
		return q
	}
	if len(b) != 1+c.size || b[0] != 2 && b[0] != 3 {
		t.Fatalf("bad point encoding %s", s)
	}
	cp := paramsOf(c)
	p := bigOf(t, cp.p)
	x := new(big.Int).SetBytes(b[1:])
	y2 := new(big.Int).Exp(x, big.NewInt(3), p)
	y2.Add(y2, new(big.Int).Mul(bigOf(t, cp.a), x))
	y2.Add(y2, bigOf(t, cp.b))
	y2.Mod(y2, p)
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		t.Fatalf("point %s: x is not on the curve", s)
	}
	if y.Bit(0) != uint(b[0]&1) {
		y.Sub(p, y)
	}
	return toPoint(t, c, x, y)
}

// compressPoint returns the compressed encoding of (x, y) (SEC 1, Section
// 2.3.3).
func compressPoint(x, y []byte) []byte {
	return append([]byte{2 | y[len(y)-1]&1}, x...)
}

// TestBotanVarPointMul checks k·P for points P other than the generator,
// with the internal scalar multiplication and, where k is a valid private
// key, with ECDH.
func TestBotanVarPointMul(t *testing.T) {
	counts := map[string]int{}
	for _, v := range botanVectors(t, "ecc_var_point_mul.vec", "Z") {
		c := botanCurves[v["Group"]]
		p := decodePoint(t, c, v["P"])
		k := katScalar(t, c, v["k"])
		want := katHex(t, v["Z"])
		x, y, ok := c.affine(c.scalarMult(p, k))
		if ok != 1 {
			t.Errorf("%s: k = %s, P = %s: k·P is the point at infinity", c.name, v["k"], v["P"])
			continue
		}
		if got := compressPoint(x, y); !bytes.Equal(got, want) {
			t.Errorf("%s: k = %s, P = %s: k·P = %x, want %x", c.name, v["k"], v["P"], got, want)
		}
		priv, err := NewPrivateKey(c, k)
		if err != nil {
			t.Fatalf("%s: k = %s: %v", c.name, v["k"], err)
		}
		px, py, _ := c.affine(p)
		peer, err := NewPublicKey(c, append([]byte{4}, append(px, py...)...))
		if err != nil {
			t.Fatal(err)
		}
		shared, err := priv.ECDH(peer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(shared, want[1:]) {
			t.Errorf("%s: k = %s, P = %s: ECDH = %x, want %x", c.name, v["k"], v["P"], shared, want[1:])
		}
		counts[c.name]++
	}
	checkBotanCounts(t, counts, 63)
}

// TestBotanBasePointMul checks k·G, the public key of k. Botan's Brainpool
// cases are the private keys of RFC 6932, Appendix A.
func TestBotanBasePointMul(t *testing.T) {
	counts := map[string]int{}
	for _, v := range botanVectors(t, "ecc_base_point_mul.vec", "P") {
		c := botanCurves[v["Group"]]
		priv, err := NewPrivateKey(c, katScalar(t, c, v["k"]))
		if err != nil {
			t.Fatalf("%s: k = %s: %v", c.name, v["k"], err)
		}
		if got, want := priv.PublicKey().Bytes(), katHex(t, v["P"]); !bytes.Equal(got, want) {
			t.Errorf("%s: k = %s: k·G = %x, want %x", c.name, v["k"], got, want)
		}
		counts[c.name]++
	}
	checkBotanCounts(t, counts, 2)
}

// botanHashes maps Botan's hash names to crypto.Hash.
var botanHashes = map[string]crypto.Hash{
	"SHA-1":   crypto.SHA1,
	"SHA-224": crypto.SHA224,
	"SHA-256": crypto.SHA256,
	"SHA-384": crypto.SHA384,
	"SHA-512": crypto.SHA512,
}

// TestBotanRFC6979 checks deterministic ECDSA signatures (RFC 6979, the
// HMAC-DRBG with the message's hash) for every hash from SHA-1 to
// SHA-512, so digests both shorter and longer than the order n.
func TestBotanRFC6979(t *testing.T) {
	counts := map[string]int{}
	for _, v := range botanVectors(t, "ecdsa_rfc6979.vec", "Signature") {
		c := botanCurves[v["Group"]]
		h, ok := botanHashes[v["Hash"]]
		if !ok {
			t.Fatalf("unknown hash %q", v["Hash"])
		}
		priv, err := NewPrivateKey(c, katScalar(t, c, v["X"]))
		if err != nil {
			t.Fatal(err)
		}
		hh := h.New()
		hh.Write(katHex(t, v["Msg"]))
		digest := hh.Sum(nil)
		want := katHex(t, v["Signature"])
		r, s, err := priv.sign(digest, h, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := append(r, s...); !bytes.Equal(got, want) {
			t.Errorf("%s/%v, message %s: r || s = %x, want %x", c.name, h, v["Msg"], got, want)
		}
		if !VerifyRaw(priv.PublicKey(), digest, want) {
			t.Errorf("%s/%v, message %s: VerifyRaw rejects the signature", c.name, h, v["Msg"])
		}
		counts[c.name]++
	}
	checkBotanCounts(t, counts, 10)
}

// checkBotanCounts guards against a parser that silently skips vectors.
func checkBotanCounts(t *testing.T, counts map[string]int, want int) {
	t.Helper()
	for _, c := range allCurves {
		if counts[c.name] != want {
			t.Errorf("%s: %d vectors, want %d", c.name, counts[c.name], want)
		}
	}
}
