//go:build ivory_kt

package main

// Expectations for the overlay profile kt.
var (
	// K1 (P7): the ECDHE_ECDSA suites first (A_17124-03 item 3,
	// A_17094-02).
	wantK1 = []uint16{0xc02b, 0xc02c, 0xc02f, 0xc030}

	// K3 (P6): one certificate type, the one that matches the suite
	// (A_22454).
	wantK3ECDSA = []byte{64}
	wantK3RSA   = []byte{1}
)
