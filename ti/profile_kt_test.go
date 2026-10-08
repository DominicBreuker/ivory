//go:build ivory && ivory_kt

package ti

// ktProfile reports whether the overlay profile kt is in use: with P6, a
// server asks only for client certificates that match the suite.
const ktProfile = true
