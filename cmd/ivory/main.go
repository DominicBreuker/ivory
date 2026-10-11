//go:build ivory

// Command ivory is a TLS test client, server and prober for the German
// health care telematics infrastructure (TI), with Brainpool certificates
// and key exchange.
//
// Usage:
//
//	ivory client [flags] host[:port]   connect once and report
//	ivory server [flags]               accept connections and report
//	ivory probe [flags] host[:port]    find out what a server supports
//	ivory tunnel [flags] host[:port]   forward local plain TCP over TLS
//	ivory proxy [flags]                HTTP proxy that does the TLS
//	ivory reverse [flags]              accept TLS, forward plain TCP
//
// Run "ivory <command> -help" for the flags. See README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `ivory: TLS test tool for the TI, with Brainpool support

usage:
  ivory client [flags] host[:port]   connect once, report the handshake and
                                     the server certificate read the TI way
  ivory server [flags]               accept connections, report what each
                                     client offers and presents
  ivory probe [flags] host[:port]    find out what a server supports, with
                                     many handshakes that each offer less
  ivory tunnel [flags] host[:port]   accept plain TCP on localhost and
                                     forward each connection over TLS
  ivory proxy [flags]                HTTP proxy on localhost that sends
                                     requests for http:// URLs over TLS
  ivory reverse -backend host:port   accept TLS and forward each
                                     connection's plain text to a local server

Run "ivory <command> -help" for the flags of a command.
`

var (
	errUsage       = errors.New("usage")
	errFailed      = errors.New("handshake failed")
	errCheckFailed = errors.New("certificate check failed")
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes a command and returns the exit status: 0 success, 1 a
// failed handshake or an error, 2 a usage error, 3 a failed TI check.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "client":
		err = runClient(args[1:], stdout, stderr)
	case "server":
		err = runServer(args[1:], stdout, stderr)
	case "probe":
		err = runProbe(args[1:], stdout, stderr)
	case "tunnel":
		err = runTunnel(args[1:], stdout, stderr)
	case "proxy":
		err = runProxy(args[1:], stdout, stderr)
	case "reverse":
		err = runReverse(args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "ivory: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	case errors.Is(err, errFailed):
		return 1
	case errors.Is(err, errCheckFailed):
		return 3
	}
	fmt.Fprintf(stderr, "ivory: %v\n", err)
	return 1
}

// parseInterspersed parses flags that may come before and after the
// positional arguments, and returns the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
