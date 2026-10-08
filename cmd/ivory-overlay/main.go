// Command ivory-overlay fetches a pinned Go release, checks it, and builds the
// ivory overlay, or a patched copy of GOROOT, from the patches in overlay/.
//
// Usage:
//
//	ivory-overlay <command> [flags]
//
// Commands:
//
//	toolchain    fetch the pinned Go release into $IVORY_CACHE/<version>
//	pin          write overlay/pins/<version>.sha256
//	build        check the pins, apply a profile, write overlay.json
//	materialize  write a patched copy of GOROOT
//	env          print shell lines to eval (GOROOT, PATH, GOTOOLCHAIN, GOFLAGS)
//	stdtest      go test -short crypto/x509 crypto/tls under the overlay (in a
//	             materialized GOROOT if the profile changes testdata)
//	bogo         run BoGo (TestBogoSuite) against a materialized GOROOT
//	doctor       report versions, pins and builds; build and run a program
//	             that uses the patched API
//	tipcheck     apply a profile to Go's development branch and report
//	             conflicts; -test also builds it and runs the tests
//	latest       print the pinned release, its newest patch release and the
//	             newest release on the module proxy
//	adopt        move to a new Go release: fetch it, re-apply and rebase the
//	             patches, re-pin, and run the test suite
//
// Run "ivory-overlay <command> -h" for the flags of a command.
//
// The tool works on the ivory module that contains the current directory (the
// first parent with overlay/GOVERSION); -root or $IVORY_ROOT name another one.
// Toolchains and build outputs go to $IVORY_CACHE (default ~/.cache/ivory),
// never into the module. It needs git, and a go command on PATH for toolchain,
// latest and adopt. Overlays can't replace files in the module cache, so the
// tool copies each toolchain out of it and runs it with GOTOOLCHAIN=local.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// A command is one subcommand of the tool.
type command struct {
	name  string
	short string
	flags func(*flag.FlagSet, *workspace) // registers the command's flags
	run   func(*workspace, []string) error
}

var commands = []*command{
	{"toolchain", "fetch the pinned Go release", goFlags, cmdToolchain},
	{"pin", "write overlay/pins/<version>.sha256", goFlags, cmdPin},
	{"build", "check the pins, apply a profile, write overlay.json", outFlags, cmdBuild},
	{"materialize", "write a patched copy of GOROOT", outFlags, cmdMaterialize},
	{"env", "print shell lines to eval", envFlags, cmdEnv},
	{"stdtest", "go test -short crypto/x509 crypto/tls under the overlay", outFlags, cmdStdtest},
	{"bogo", "run BoGo against a materialized GOROOT", bogoFlags, cmdBogo},
	{"doctor", "report versions, pins and builds; run a check program", envFlags, cmdDoctor},
	{"tipcheck", "apply a profile to Go's development branch", tipFlags, cmdTipcheck},
	{"latest", "print the newest Go releases", goFlags, cmdLatest},
	{"adopt", "move to a new Go release and test it", adoptFlags, cmdAdopt},
}

// errConflict reports a failure that the command already explained on
// standard output; main only sets the exit status.
var errConflict = errors.New("conflicts")

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "help" {
		usage(stderr)
		return 2
	}
	var cmd *command
	for _, c := range commands {
		if c.name == args[0] {
			cmd = c
		}
	}
	if cmd == nil {
		fmt.Fprintf(stderr, "ivory-overlay: unknown command %s (run without arguments for help)\n", args[0])
		return 2
	}
	w := &workspace{profile: "core"}
	fs := flag.NewFlagSet("ivory-overlay "+cmd.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&w.root, "root", "", "the ivory module (default: $IVORY_ROOT, or the first parent directory with overlay/GOVERSION)")
	cmd.flags(fs, w)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if err := w.init(); err != nil {
		fmt.Fprintf(stderr, "ivory-overlay: %v\n", err)
		return 1
	}
	if err := cmd.run(w, fs.Args()); err != nil {
		if err != errConflict {
			fmt.Fprintf(stderr, "ivory-overlay: %v\n", err)
		}
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: ivory-overlay <command> [flags]\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.short)
	}
	fmt.Fprintf(w, "\nRun \"ivory-overlay <command> -h\" for the flags of a command.\n"+
		"Environment: IVORY_CACHE (default ~/.cache/ivory), IVORY_ROOT.\n")
}

func goFlags(fs *flag.FlagSet, w *workspace) {
	fs.StringVar(&w.version, "go", "", "Go release (default: overlay/GOVERSION)")
}

func profileFlags(fs *flag.FlagSet, w *workspace) {
	goFlags(fs, w)
	fs.StringVar(&w.profile, "profile", "core", "patch profile from overlay/profiles")
}

func outFlags(fs *flag.FlagSet, w *workspace) {
	profileFlags(fs, w)
	fs.StringVar(&w.out, "o", "", "output directory (build: the overlay; materialize: the GOROOT copy)")
}

func envFlags(fs *flag.FlagSet, w *workspace) {
	outFlags(fs, w)
	fs.BoolVar(&w.materialized, "materialized", false, "use a materialized GOROOT instead of the overlay")
}

func bogoFlags(fs *flag.FlagSet, w *workspace) {
	outFlags(fs, w)
	fs.StringVar(&w.filter, "filter", "", "BoGo test name pattern (-bogo-filter); lists the selected tests")
}

// logf writes a progress message to standard error.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ivory-overlay: "+format+"\n", args...)
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
