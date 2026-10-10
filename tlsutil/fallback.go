//go:build ivory

package tlsutil

import (
	"crypto/tls"
	"slices"
	"sync"
)

// TLS12Fallback returns a function for config.GetConfigForClient that
// answers in TLS 1.2 a client that asks for TLS 1.3 but can use none of
// certs there, because it supports Brainpool only with the TLS 1.2 code
// points. Windows SChannel (and so .NET's SslStream on Windows) is such a
// client: in TLS 1.3 it offers the Brainpool groups as 26-28, the TLS 1.2
// code points, and none of the signature schemes 0x081A-0x081C of RFC
// 8734, so no TLS 1.3 handshake with a Brainpool certificate is possible,
// while TLS 1.2 works.
//
// The connection falls back to TLS 1.2 only if all of these hold:
//
//   - config allows TLS 1.2 and TLS 1.3, and the client offers both;
//   - the client offers a Brainpool group for TLS 1.2 (26-28) and none
//     of the TLS 1.3 Brainpool signature schemes (0x081A-0x081C);
//   - none of certs can be used in TLS 1.3 with this client
//     (tls.ClientHelloInfo.SupportsCertificate), and one of them can be
//     used in TLS 1.2 (SupportsCertificate).
//
// So the fallback only turns a handshake that would fail into a TLS 1.2
// handshake; every other client, an RFC 8734 client in particular, gets
// the same answer as without it. For the fallback, the function returns a
// copy of config with MaxVersion TLS 1.2: the server then doesn't support
// TLS 1.3 for that connection and sends no downgrade sentinel (RFC 8446,
// Section 4.1.3). An attacker can't use this to downgrade other clients:
// the decision depends on the ClientHello, which the TLS 1.2 Finished
// messages cover, so a ClientHello changed on the way fails the handshake.
// The TLS 1.2 settings of config (cipher suites, groups) apply as they
// are; make sure they are what you want.
//
// certs are the identities the server offers, as passed to
// GetCertificate, or config.Certificates if certs is nil. config must not
// be changed after the first handshake; a GetConfigForClient it already
// has is not called.
func TLS12Fallback(config *tls.Config, certs []tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	var (
		once     sync.Once
		fallback *tls.Config
	)
	return func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if !needsTLS12Fallback(config, certs, chi) {
			return nil, nil
		}
		once.Do(func() {
			fallback = config.Clone()
			fallback.MaxVersion = tls.VersionTLS12
			fallback.GetConfigForClient = nil
		})
		return fallback, nil
	}
}

func needsTLS12Fallback(config *tls.Config, certs []tls.Certificate, chi *tls.ClientHelloInfo) bool {
	if certs == nil {
		certs = config.Certificates
	}
	if len(certs) == 0 ||
		config.MinVersion > tls.VersionTLS12 || (config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13) ||
		!slices.Contains(chi.SupportedVersions, tls.VersionTLS13) || !slices.Contains(chi.SupportedVersions, tls.VersionTLS12) {
		return false
	}
	if !slices.ContainsFunc(chi.SupportedCurves, func(id tls.CurveID) bool {
		return id == CurveBrainpoolP256r1 || id == CurveBrainpoolP384r1 || id == CurveBrainpoolP512r1
	}) {
		return false
	}
	if slices.ContainsFunc(chi.SignatureSchemes, func(s tls.SignatureScheme) bool {
		h, _ := tls13Scheme(s)
		return h != 0
	}) {
		return false
	}
	// chi.SupportsCertificate checks the highest version both support,
	// TLS 1.3 here; tls12 is the same ClientHello limited to TLS 1.2.
	tls12 := *chi
	tls12.SupportedVersions = []uint16{tls.VersionTLS12}
	usable12 := false
	for i := range certs {
		if chi.SupportsCertificate(&certs[i]) == nil {
			return false
		}
		if SupportsCertificate(&tls12, &certs[i]) == nil {
			usable12 = true
		}
	}
	return usable12
}
