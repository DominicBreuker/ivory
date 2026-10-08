// Package interop holds interoperability tests: Go with the ivory overlay
// against OpenSSL (openssl s_server and s_client), against BouncyCastle's
// TLS provider for Java, and Go against Go. It has no non-test code;
// README.md lists the tests.
//
// The tests need the overlay and the build tag ivory. Tests that need
// OpenSSL are skipped if the openssl command is missing. They use the
// test PKI in testdata/pki.
//
// The TLS 1.3 tests against OpenSSL need OpenSSL 3.2 or later, which has
// the Brainpool groups and signature schemes of RFC 8734 in TLS 1.3. They
// run the binary named by IVORY_OPENSSL3, or openssl, and are skipped if
// it is older; with IVORY_REQUIRE_TLS13 set, they fail instead.
//
// The BouncyCastle tests need a JDK and the jars in the directory
// IVORY_BCJARS (scripts/fetch-bouncycastle.sh); they are skipped without
// them, unless IVORY_REQUIRE_BC is set.
package interop
