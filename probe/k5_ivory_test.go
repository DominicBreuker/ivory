//go:build ivory

package main

// With the overlay (patch P0, both profiles), the server refuses the
// renegotiation with a fatal no_renegotiation alert (GS-A_5524).
const (
	wantK5Alert       = "<<< TLS 1.2, Alert [length 0002], fatal no_renegotiation"
	wantK5ServerError = "local error: tls: no renegotiation"
)
