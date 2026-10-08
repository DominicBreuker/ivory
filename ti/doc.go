// Package ti provides crypto/tls configurations for the German health care
// telematics infrastructure (TI), as specified by gematik in gemSpec_Krypt
// V2.51.0 and gemSpec_KT V3.17.1.
//
// Every preset uses TLS 1.2 only, the TI cipher suites of the role, the
// groups P-256, P-384, brainpoolP256r1 and brainpoolP384r1, Brainpool
// signature verification from package tlsutil, and checks the peer's
// certificate in VerifyConnection with a Verifier: the TI's two-level
// check of an end-entity certificate against stored CA certificates,
// without path building.
//
// The presets need the ivory overlay and the build tag ivory; without them
// only Verifier, the session helpers and the constants compile.
//
// Programs that use the presets should also disable SHA-1 in TLS
// signatures (A_21275-01) with
//
//	//go:debug tlssha1=0
//
// in their main package (the default since Go 1.25).
package ti
