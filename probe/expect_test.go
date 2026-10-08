//go:build !ivory_kt

package main

// Expectations for stock Go 1.27.1 and the overlay profile core.
var (
	// K1: Go fixes the order and ignores the order of Config.CipherSuites:
	// ECDSA-128, RSA-128, ECDSA-256, RSA-256.
	wantK1 = []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030}

	// K3: rsa_sign and ecdsa_sign on every suite.
	wantK3ECDSA = []byte{1, 64}
	wantK3RSA   = []byte{1, 64}
)
