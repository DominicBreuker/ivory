package ti

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/DominicBreuker/ivory/x509util"
)

// Certificate policies of TI end-entity certificates (gemSpec_OID V3.26.0).
var (
	PolicySMKTAUT = mustOID("1.2.276.0.76.4.82")  // C.SMKT.AUT: eHealth-KT identity on the gSMC-KT
	PolicySAKAUT  = mustOID("1.2.276.0.76.4.113") // C.SAK.AUT: Konnektor identity towards the eHealth-KT
	PolicyAKAUT   = mustOID("1.2.276.0.76.4.79")  // C.AK.AUT: Anwendungskonnektor
	PolicyNKVPN   = mustOID("1.2.276.0.76.4.80")  // C.NK.VPN: Netzkonnektor
	PolicyFDTLSC  = mustOID("1.2.276.0.76.4.168") // C.FD.TLS-C: Fachdienst TLS client
	PolicyFDTLSS  = mustOID("1.2.276.0.76.4.169") // C.FD.TLS-S: Fachdienst TLS server
)

func mustOID(s string) x509.OID {
	oid, err := x509.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return oid
}

// A Verifier checks a peer's end-entity certificate the way TI products do:
// the certificate must be issued directly by one of the stored CA
// certificates (two levels, no path building; gemSpec_KT A_22888,
// gemSpec_PKI TUC_PKI_018). CA certificates sent by the peer are never
// used. Signatures are checked with package x509util, so keys may be
// Brainpool keys.
type Verifier struct {
	// CAs are the trusted issuing CA certificates. They must be CAs whose
	// keyUsage, if present, allows keyCertSign.
	CAs []*x509.Certificate

	// KeyUsage are the keyUsage bits the certificate must have, if not 0.
	KeyUsage x509.KeyUsage

	// ExtKeyUsages are the extended key usages the certificate must list.
	ExtKeyUsages []x509.ExtKeyUsage

	// Policies, if not empty, are the certificate policies of which the
	// certificate must list at least one.
	Policies []x509.OID

	// CRLs are the revocation lists the Verifier consults. If a CRL's CA
	// issued the certificate, the CRL must be valid, and the certificate
	// must not be on it.
	CRLs []CRL

	// RequireCRL makes certificates fail whose CA has no entry in CRLs.
	RequireCRL bool

	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time
}

// A CRL is a certificate revocation list for the certificates that CA
// issued.
type CRL struct {
	List *x509.RevocationList
	CA   *x509.Certificate

	// Signer is the certificate that signed List. If nil, CA signed it.
	// In the TI, CRL signers are certificates of their own with cA =
	// FALSE (profile C.GEM.CRL); Signer is trusted as configured.
	Signer *x509.Certificate
}

// Verify checks leaf. If dnsName is not empty, leaf must be valid for it.
func (v *Verifier) Verify(leaf *x509.Certificate, dnsName string) error {
	if leaf == nil {
		return errors.New("ti: no peer certificate")
	}
	now := time.Now()
	if v.Time != nil {
		now = v.Time()
	}
	if err := checkValidity(leaf, now); err != nil {
		return err
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return fmt.Errorf("ti: certificate %q is a CA certificate", leaf.Subject)
	}
	var ca *x509.Certificate
	var caErr error
	for _, c := range v.CAs {
		if !bytes.Equal(leaf.RawIssuer, c.RawSubject) {
			continue
		}
		if err := x509util.CheckCertificateSignatureFrom(leaf, c); err != nil {
			caErr = err
			continue
		}
		ca = c
		break
	}
	if ca == nil {
		if caErr != nil {
			return fmt.Errorf("ti: certificate %q: bad signature by its CA: %w", leaf.Subject, caErr)
		}
		return fmt.Errorf("ti: certificate %q is not issued by a trusted CA", leaf.Subject)
	}
	if err := checkValidity(ca, now); err != nil {
		return err
	}
	if v.KeyUsage != 0 && leaf.KeyUsage&v.KeyUsage != v.KeyUsage {
		return fmt.Errorf("ti: certificate %q lacks key usage %#x", leaf.Subject, v.KeyUsage)
	}
	for _, eku := range v.ExtKeyUsages {
		if !slices.Contains(leaf.ExtKeyUsage, eku) {
			return fmt.Errorf("ti: certificate %q lacks extended key usage %v", leaf.Subject, eku)
		}
	}
	if len(v.Policies) > 0 && !slices.ContainsFunc(leaf.Policies, func(p x509.OID) bool {
		return slices.ContainsFunc(v.Policies, p.Equal)
	}) {
		return fmt.Errorf("ti: certificate %q has none of the policies %v", leaf.Subject, v.Policies)
	}
	if dnsName != "" {
		if err := leaf.VerifyHostname(dnsName); err != nil {
			return err
		}
	}
	return v.checkRevocation(leaf, ca, now)
}

func (v *Verifier) checkRevocation(leaf, ca *x509.Certificate, now time.Time) error {
	found := false
	for _, crl := range v.CRLs {
		if crl.CA == nil || !bytes.Equal(crl.CA.Raw, ca.Raw) {
			continue
		}
		found = true
		signer := crl.Signer
		if signer == nil {
			signer = ca
		}
		if !bytes.Equal(crl.List.RawIssuer, signer.RawSubject) {
			return fmt.Errorf("ti: CRL for %q is not issued by its signer %q", ca.Subject, signer.Subject)
		}
		if err := x509util.CheckCRLSignatureFrom(crl.List, signer); err != nil {
			return fmt.Errorf("ti: CRL for %q: bad signature: %w", ca.Subject, err)
		}
		if now.Before(crl.List.ThisUpdate) || !crl.List.NextUpdate.IsZero() && now.After(crl.List.NextUpdate) {
			return fmt.Errorf("ti: CRL for %q is not current at %v", ca.Subject, now.UTC().Format(time.RFC3339))
		}
		for _, e := range crl.List.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return fmt.Errorf("ti: certificate %q is revoked", leaf.Subject)
			}
		}
	}
	if !found && v.RequireCRL {
		return fmt.Errorf("ti: no CRL for the CA %q", ca.Subject)
	}
	return nil
}

func checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("ti: certificate %q is not valid at %v (valid from %v to %v)",
			c.Subject, now.UTC().Format(time.RFC3339), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
