package brainpool_test

// The Brainpool test vectors of gemSpec_Krypt V2.51.0 (gematik), recomputed
// with this package. The values are the ones printed in the specification.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// gemRCA3 is the example X.509 root GEM.RCA3 of gemSpec_Krypt, Section 4.2.
const gemRCA3 = `-----BEGIN CERTIFICATE-----
MIICajCCAg+gAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMG
A1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRl
ciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBMzAeFw0x
NjEyMDkwODQxNTZaFw0yNjEyMDcwODQxNTZaMG0xCzAJBgNVBAYTAkRFMRUwEwYD
VQQKDAxnZW1hdGlrIEdtYkgxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVy
IFRlbGVtYXRpa2luZnJhc3RydWt0dXIxETAPBgNVBAMMCEdFTS5SQ0EzMFowFAYH
KoZIzj0CAQYJKyQDAwIIAQEHA0IABDd0NFCa3LuCf3Ss163wznKqKN3FO+PxXqgC
OpsHIsCdU2SplobAIJK7+e/emHiEe5DwnZC3rEGTVTggJYpY39WjgZ4wgZswHQYD
VR0OBBYEFBERSneTkJZDKt3uLzjddI870TMmMEIGCCsGAQUFBwEBBDYwNDAyBggr
BgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3Aw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFQYDVR0gBA4wDDAKBggq
ghQATASBIzAKBggqhkjOPQQDAgNJADBGAiEApQ6qGHTx97IsdzgoWH9/W32yt4rk
udUis0xxGZ48YOUCIQCTQ4puol5YYIAZYk74mfid3JBOvMBV/XgPV2WpS/99yg==
-----END CERTIFICATE-----
`

func hexBytes(t *testing.T, s string) []byte { return mustDecodeHex(t, s) }

// TestGemSpecRCA3 reproduces Section 4.2: the private key is d = SHA-256 of
// a label. The text says to read d little-endian ("Dieses d wird als
// Ganzzahl (Little-Endian) interpretiert"), but only big-endian reproduces
// the published point: an erratum in the specification.
func TestGemSpecRCA3(t *testing.T) {
	d := sha256.Sum256([]byte("gemSpec_Krypt-Beispiel X.509-Root-TI ECDSA-Schluessel"))
	if got := hex.EncodeToString(d[:]); got != "62e50dca4da29b0b10ead635a20b51fb1ec281d11f90cde8b5a9d92371ae8052" {
		t.Fatalf("d = %s", got)
	}
	wantPoint := "04" +
		"377434509adcbb827f74acd7adf0ce72aa28ddc53be3f15ea8023a9b0722c09d" +
		"5364a99686c02092bbf9efde9878847b90f09d90b7ac4193553820258a58dfd5"

	k, err := brainpool.NewPrivateKey(brainpool.P256r1(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k.PublicKey().Bytes()); got != wantPoint {
		t.Errorf("big-endian d: point %s, want %s", got, wantPoint)
	}
	le := make([]byte, len(d))
	for i := range d {
		le[i] = d[len(d)-1-i]
	}
	if kle, err := brainpool.NewPrivateKey(brainpool.P256r1(), le); err == nil && hex.EncodeToString(kle.PublicKey().Bytes()) == wantPoint {
		t.Error("little-endian d reproduces the point too; the erratum note is wrong")
	}

	// The SubjectPublicKeyInfo printed in Section 4.2.
	spki, _ := base64.StdEncoding.DecodeString("MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDd0NFCa3LuCf3Ss163wznKqKN3FO+PxXqgCOpsHIsCdU2SplobAIJK7+e/emHiEe5DwnZC3rEGTVTggJYpY39U=")
	if got, err := x509util.MarshalPKIXPublicKey(k.PublicKey()); err != nil || !bytes.Equal(got, spki) {
		t.Errorf("SPKI differs from the specification: %v", err)
	}

	// The certificate's self-signature (ecdsa-with-SHA256).
	block, _ := pem.Decode([]byte(gemRCA3))
	tbs, sig := certParts(t, block.Bytes)
	if err := x509util.CheckSignature(x509.ECDSAWithSHA256, tbs, sig, k.PublicKey()); err != nil {
		t.Errorf("GEM.RCA3 self-signature: %v", err)
	}
	pub, err := x509util.ParsePKIXPublicKey(spki)
	if err != nil || !k.PublicKey().Equal(pub) {
		t.Errorf("ParsePKIXPublicKey(SPKI) = %v, %v", pub, err)
	}

	// With the ivory overlay, crypto/x509 parses the certificate too.
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if err := x509util.CheckCertificateSignatureFrom(cert, cert); err != nil {
			t.Errorf("CheckCertificateSignatureFrom(GEM.RCA3, GEM.RCA3): %v", err)
		}
	}
}

// certParts returns the TBSCertificate and the signature of a certificate.
func certParts(t *testing.T, der []byte) (tbs, sig []byte) {
	t.Helper()
	input := cryptobyte.String(der)
	var outer, raw cryptobyte.String
	var bits cryptobyte.String
	if !input.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.ReadASN1Element(&raw, cbasn1.SEQUENCE) ||
		!outer.SkipASN1(cbasn1.SEQUENCE) || !outer.ReadASN1(&bits, cbasn1.BIT_STRING) || len(bits) < 1 || bits[0] != 0 {
		t.Fatal("malformed certificate")
	}
	return raw, bits[1:]
}

// TestGemSpecA20161 reproduces the E-Rezept VAU ECIES example of A_20161-01:
// ephemeral key, ECDH shared secret, HKDF-SHA-256 content key and
// AES-128-GCM ciphertext.
func TestGemSpecA20161(t *testing.T) {
	c := brainpool.P256r1()
	vau, err := brainpool.NewPublicKey(c, hexBytes(t, "04"+
		"8634212830dad457ca05305e6687134166b9c21a65ffebf555f4e75dfb048888"+
		"66e4b6843624cbda43c97ea89968bc41fd53576f82c03efa7d601b9facac2b29"))
	if err != nil {
		t.Fatal(err)
	}
	eph, err := brainpool.NewPrivateKey(c, hexBytes(t, "5bbba34d47502bd588ed680dfa2309ca375eb7a35ddbbd67cc7f8b6b687a1c1d"))
	if err != nil {
		t.Fatal(err)
	}
	wantEph := "04" +
		"754e548941e5cd073fed6d734578a484be9f0bbfa1b6fa3168ed7ffb22878f0f" +
		"9aef9bbd932a020d8828367bd080a3e72b36c41ee40c87253f9b1b0beb8371bf"
	if got := hex.EncodeToString(eph.PublicKey().Bytes()); got != wantEph {
		t.Errorf("ephemeral public key %s, want %s", got, wantEph)
	}
	shared, err := eph.ECDH(vau)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(shared); got != "9656c2b4b3da81d0385f6a1ee60e93b91828fd90231c923d53ce7bbbcd58ceaa" {
		t.Errorf("shared secret %s", got)
	}
	cek, err := hkdf.Key(sha256.New, shared, nil, "ecies-vau-transport", 16)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(cek); got != "23977ba552a21363916af9b5147c83d4" {
		t.Errorf("CEK %s", got)
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, hexBytes(t, "257db4604af8ae0dfced37ce"), []byte("Hallo Test"), nil)
	if got := hex.EncodeToString(ct); got != "86c2b491c7a8309e750b"+"4e6e307219863938c204dfe85502ee0a" {
		t.Errorf("ciphertext and tag %s", got)
	}
}

// TestGemSpecA23463 decrypts the ECIES export of the VSDM HMAC key in
// A_23463 with the example VAU key, given as a SEC 1 key.
func TestGemSpecA23463(t *testing.T) {
	const keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHgCAQEEII1+MNpxZfd+cPjE1Z5DCHCnuGCQt5MA6U55yuaxoB8CoAsGCSskAwMC
CAEBB6FEA0IABB1wleU9eglD8Q7j7HuTVyG7KJIRoJ6Rt1x8+GHvb3xeht3f5RPe
ETi+py3tLK5RWhFeGOIKmnydoBxJmK6Vcmg=
-----END EC PRIVATE KEY-----
`
	block, _ := pem.Decode([]byte(keyPEM))
	k, err := x509util.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	blob := hexBytes(t, "019dec56554203624c214ac5321c798b78281d3fff4a0a4e187319ebebeba2ace40fe71913c6e02998cd3c"+
		"d6f8268a0daf9f40eb1561541de9868d46eb913e3f3157d5ed6bd9d4aef792d473be5fa2868dbcd228e5a603"+
		"afdae2c69fc459e656513cff835934de5e2f159b772ebbd21d6dfef2a4960ad829b968fc974b")
	if blob[0] != 1 {
		t.Fatalf("version byte %x", blob[0])
	}
	shared, err := k.Decapsulate(append([]byte{4}, blob[1:65]...))
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := hkdf.Key(sha256.New, shared, nil, "ecies-vau-transport", 16)
	aesBlock, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(aesBlock)
	pt, err := gcm.Open(nil, blob[65:77], blob[77:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pt); got != "3a8e0064436bf2dbe7ca41ec6f1ed60beec083bc4100633281eb397cb294391c" {
		t.Errorf("HMAC key %s", got)
	}
}

// TestGemSpecCardECIES checks that the ephemeral point of the
// card-compatible ECIES example (Section 4.7) is on brainpoolP256r1.
func TestGemSpecCardECIES(t *testing.T) {
	blob, err := base64.StdEncoding.DecodeString(
		"poGOBgkrJAMDAggBAQd/SUOGQQRouC6tM2TQQ+RP3pptgdAaDF8Te7IVCkUBe2H+PJSLK4W/BXIX" +
			"kndiBwEfftd5wk4pjzCdC2j1q14/CIWcW89nhjEC7G47UAu2ZqmbIhxstkXV3UI2UUek/qwBwtb2" +
			"6aUild+5kkTZXf5674OKHSdj6IFwjggvhYt9b/CTsA==")
	if err != nil {
		t.Fatal(err)
	}
	// [6] { OID, [APPLICATION 73] { [6] PO }, … }: PO follows
	// A6 81 8E | 06 09 <oid> | 7F 49 43 | 86 41.
	if _, err := brainpool.NewPublicKey(brainpool.P256r1(), blob[19:19+65]); err != nil {
		t.Errorf("PO: %v", err)
	}
}
