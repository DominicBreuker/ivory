// Package tlsutil plugs Brainpool keys and groups into crypto/tls through
// the extension points of the ivory overlay: Config.VerifyUnsupportedSignature
// verifies the peer's signatures, Config.KeyExchanges adds the Brainpool
// groups, and Certificate.SupportedSignatureAlgorithms lets crypto/tls sign
// with a Brainpool key it doesn't know (NewSigner, RawSigner, Certificate,
// X509KeyPair).
//
// The same works in TLS 1.3 (RFC 8734): KeyExchanges includes the TLS 1.3
// groups 31-33, the signers implement crypto.MessageSigner for the TLS 1.3
// signature schemes 0x081A-0x081C, and SignatureSchemes is a list for
// Config.SignatureSchemes that includes them, which a TLS 1.3 peer needs to
// present or accept a Brainpool certificate. The ti presets stay on TLS 1.2.
//
// Most of the package needs the overlay and the build tag ivory:
//
//	GOFLAGS="-overlay=/abs/path/overlay.json -tags=ivory"
//
// Without them, only ChainVerifier compiles, and importers of the rest
// fail with "undefined: tlsutil...".
//
// The Brainpool arithmetic comes from package brainpool, key parsing and
// certificate signature checks from package x509util.
package tlsutil
