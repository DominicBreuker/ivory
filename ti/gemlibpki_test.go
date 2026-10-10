//go:build ivory

package ti

// Certificates of gematik's TI test PKI, as published with gematik's
// reference PKI library GemLibPki, checked with Verifier: the library's
// own valid and invalid end-entity certificates for an SMC-B (C.HCI.AUT),
// and identities of other card and component types under Brainpool,
// NIST P-256 and RSA CAs. The certificates are downloaded by
// scripts/fetch-gemlibpki.sh into the directory $IVORY_GEMLIBPKI; the test
// is skipped without it, unless $IVORY_REQUIRE_GEMLIBPKI is set.

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Certificate policies of the profiles below (gemSpec_OID V3.26.0).
var (
	policyHCIAUT = mustOID("1.2.276.0.76.4.77") // C.HCI.AUT: SMC-B
	policyHPAUT  = mustOID("1.2.276.0.76.4.75") // C.HP.AUT: HBA
	policyCHAUT  = mustOID("1.2.276.0.76.4.70") // C.CH.AUT: eGK
)

func readGemLibPki(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	c, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

func TestGemLibPki(t *testing.T) {
	dir := os.Getenv("IVORY_GEMLIBPKI")
	if dir == "" {
		if os.Getenv("IVORY_REQUIRE_GEMLIBPKI") != "" {
			t.Fatal("IVORY_GEMLIBPKI is not set (scripts/fetch-gemlibpki.sh)")
		}
		t.Skip("IVORY_GEMLIBPKI is not set (scripts/fetch-gemlibpki.sh)")
	}
	read := func(name string) *x509.Certificate { return readGemLibPki(t, dir, name) }

	// All CAs at once: Verifier picks the issuer by name, key identifier
	// and signature.
	cas := []*x509.Certificate{
		read("GEM.SMCB-CA57/GEM.SMCB-CA57-TEST-ONLY.pem"),
		read("GEM.KOMP-CA57/GEM.KOMP-CA57-TEST-ONLY.pem"),
		read("GEM.HBA-CA57/GEM.HBA-CA57-TEST-ONLY.pem"),
		read("GEM.KOMP-CA61/GEM.KOMP-CA61-TEST-ONLY.pem"),
		read("GEM.SMCB-CA41-RSA/GEM.SMCB-CA41.pem"),
		read("GEM.EGK-CA51/GEM.EGK-CA51-TEST-ONLY.pem"),
	}
	at := func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	// The profiles as GemLibPki defines them (CertificateProfile.java).
	profile := func(ku x509.KeyUsage, policy x509.OID, ekus ...x509.ExtKeyUsage) *Verifier {
		return &Verifier{CAs: cas, KeyUsage: ku, ExtKeyUsages: ekus, Policies: []x509.OID{policy}, Time: at}
	}
	hciAUT := profile(x509.KeyUsageDigitalSignature, policyHCIAUT, x509.ExtKeyUsageClientAuth)
	akAUT := profile(x509.KeyUsageDigitalSignature, PolicyAKAUT, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)
	hpAUT := profile(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement, policyHPAUT, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection)
	fdTLSC := profile(x509.KeyUsageDigitalSignature, PolicyFDTLSC, x509.ExtKeyUsageClientAuth)
	chAUT := profile(x509.KeyUsageDigitalSignature, policyCHAUT)

	for _, tt := range []struct {
		file    string
		v       *Verifier
		dnsName string
		wantErr string // "" for a certificate GemLibPki accepts
	}{
		// SMC-B, brainpoolP256r1 under GEM.SMCB-CA57: GemLibPki's valid ...
		{"GEM.SMCB-CA57/valid/PraxisBabetteBeyer.pem", hciAUT, "", ""},
		{"GEM.SMCB-CA57/valid/Beyer-Zahnarzt.crt", hciAUT, "", ""},
		{"GEM.SMCB-CA57/valid/BabetteBeyer-invalid-extension-not-crit.pem", hciAUT, "", ""},
		{"GEM.SMCB-CA57/valid/BabetteBeyer-missing-admission.pem", hciAUT, "", ""},
		{"GEM.SMCB-CA57/valid/BabetteBeyer-missing-prof-oid.pem", hciAUT, "", ""},
		// ... and invalid certificates.
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-expired.pem", hciAUT, "", "not valid at"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-not-yet-valid.pem", hciAUT, "", "not valid at"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-signature.pem", hciAUT, "", "bad signature"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-selfsigned.pem", hciAUT, "", "not issued by a trusted CA"},
		// Despite its name, issued (correctly) by GEM.SMCB-CA58, which is
		// not among the trusted CAs.
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-authorityKeyId.pem", hciAUT, "", "not issued by a trusted CA"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-extension-crit.pem", hciAUT, "", "unhandled critical extension"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-keyusage.pem", hciAUT, "", "lacks key usage"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-missing-keyUsage.pem", hciAUT, "", "lacks key usage"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-ext-keyusage.pem", hciAUT, "", "extended key usage"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-missing-extKeyUsage.pem", hciAUT, "", "extended key usage"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-invalid-certificate-type.pem", hciAUT, "", "none of the policies"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-missing-certificate-type.pem", hciAUT, "", "none of the policies"},
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-missing-policyId.pem", hciAUT, "", "none of the policies"},
		// GemLibPki rejects a certificate without an authority key
		// identifier, because it finds the issuer by that identifier.
		// Verifier finds it by name and signature and accepts it.
		{"GEM.SMCB-CA57/invalid/BabetteBeyer-missing-authorityKeyId.pem", hciAUT, "", ""},

		// Anwendungskonnektor (C.AK.AUT), brainpoolP256r1 under GEM.KOMP-CA57.
		{"GEM.KOMP-CA57/80276883110000000001-20250721_ecc.crt", akAUT, "konnektor.konlan", ""},
		{"GEM.KOMP-CA57/80276883110000000001-20250721_ecc.crt", akAUT, "kt.konlan", "not kt.konlan"},
		{"GEM.KOMP-CA57/80276883110000000001-20250721_ecc.crt", KonnektorVerifier(cas), "", "none of the policies"},
		// HBA (C.HP.AUT), brainpoolP256r1 under GEM.HBA-CA57.
		{"GEM.HBA-CA57/BabetteBeyer.pem", hpAUT, "", ""},
		// Fachdienst TLS client (C.FD.TLS-C), P-256 under GEM.KOMP-CA61.
		{"GEM.KOMP-CA61/ee_komp_nist_test.pem", fdTLSC, "", ""},
		// SMC-B (C.HCI.AUT), RSA 2048 under GEM.SMCB-CA41.
		{"GEM.SMCB-CA41-RSA/Aschoffsche_Apotheke-AUT-RSA.pem", hciAUT, "", ""},
		// eGK (C.CH.AUT), brainpoolP256r1 under GEM.EGK-CA51.
		{"GEM.EGK-CA51/LetitiaBeutelsbacher.pem", chAUT, "", ""},
		{"GEM.EGK-CA51/LetitiaBeutelsbacher.pem", hciAUT, "", "extended key usage"},
	} {
		t.Run(tt.file, func(t *testing.T) {
			if tt.v.Time == nil {
				tt.v.Time = at
			}
			err := tt.v.Verify(read(tt.file), tt.dnsName)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
