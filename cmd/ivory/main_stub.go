//go:build !ivory

// Command ivory needs the ivory overlay and the build tag ivory; see
// README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ivory: built without the ivory overlay; build it with the overlay and -tags=ivory (see README.md)")
	os.Exit(1)
}
