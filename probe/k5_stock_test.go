//go:build !ivory

package main

// Stock Go answers a renegotiating ClientHello with a fatal
// unexpected_message alert, which GS-A_5524 doesn't allow.
const (
	wantK5Alert       = "<<< TLS 1.2, Alert [length 0002], fatal unexpected_message"
	wantK5ServerError = "received unexpected handshake message of type *tls.clientHelloMsg"
)
