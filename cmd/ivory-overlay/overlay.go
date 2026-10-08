package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func noArgs(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
	}
	return nil
}

// hostGoEnv is the environment for the go command on PATH, which only
// downloads: it must use its own GOROOT, and GOFLAGS from an ivory env
// (an overlay, build tags) must not reach it.
func hostGoEnv(extra ...string) []string {
	env := environ([]string{"GOROOT", "GOTOOLCHAIN", "GOFLAGS"})
	if os.Getenv("GOPROXY") == "" {
		env = append(env, "GOPROXY=https://proxy.golang.org")
	}
	return append(append(env, "GOTOOLCHAIN=local"), extra...)
}

func cmdToolchain(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	return w.fetchToolchain()
}

// fetchToolchain downloads w.version from the module proxy, verified by the
// checksum database, and copies it to w.goroot(): overlays can't replace
// files in GOMODCACHE.
func (w *workspace) fetchToolchain() error {
	g := w.goroot()
	goBin := filepath.Join(g, "bin", "go")
	if _, err := os.Stat(goBin); err == nil {
		v, err := output("", goEnv(g, ""), goBin, "version")
		if err != nil {
			return err
		}
		logf("toolchain present: %s", strings.TrimSpace(v))
		return nil
	}
	goCmd, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("toolchain needs an installed go command (any Go >= 1.22) to download %s", w.version)
	}
	if err := os.MkdirAll(w.cache, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(w.cache, "dl.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	mod := fmt.Sprintf("golang.org/toolchain@v0.0.1-%s.%s-%s", w.version, runtime.GOOS, runtime.GOARCH)
	out, err := output(tmp, hostGoEnv("GOFLAGS=-mod=mod", "GOMODCACHE="+filepath.Join(w.cache, "gomod")),
		goCmd, "mod", "download", "-json", mod)
	var info struct{ Dir, Error string }
	if jerr := json.Unmarshal([]byte(out), &info); err != nil || jerr != nil || info.Error != "" || info.Dir == "" {
		return fmt.Errorf("download of %s failed: %v %s", mod, err, info.Error)
	}
	staging := g + ".tmp"
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := copyTree(info.Dir, staging); err != nil {
		return err
	}
	// The module zip drops the exec bits.
	execs, _ := filepath.Glob(filepath.Join(staging, "bin", "*"))
	tools, _ := filepath.Glob(filepath.Join(staging, "pkg", "tool", "*", "*"))
	for _, f := range append(execs, tools...) {
		if err := os.Chmod(f, 0o755); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, g); err != nil {
		return err
	}
	v, err := output("", goEnv(g, ""), goBin, "version")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(v, "go version "+w.version+" ") {
		return fmt.Errorf("unexpected version: %s", strings.TrimSpace(v))
	}
	logf("installed %s at %s", strings.TrimSpace(v), g)
	return nil
}

func cmdPin(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	if err := w.needGoroot(); err != nil {
		return err
	}
	ps, err := w.allPatches()
	if err != nil {
		return err
	}
	files := pristineFiles(ps)
	if err := writePins(w.pinsFile(), w.goroot(), files); err != nil {
		return err
	}
	logf("wrote %s (%d files)", w.pinsFile(), len(files))
	return nil
}

// within reports whether dir is parent or inside it.
func within(dir, parent string) bool {
	rel, err := filepath.Rel(parent, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// outputDir makes dir absolute and checks that it is outside GOROOT and the
// module cache.
func (w *workspace) outputDir(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if within(dir, w.goroot()) || within(dir, filepath.Join(w.cache, "gomod")) || within(w.root, dir) {
		return "", fmt.Errorf("output %s must be outside GOROOT, GOMODCACHE and the ivory module", dir)
	}
	return dir, nil
}

func cmdBuild(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	dir, err := w.build()
	if err != nil {
		return err
	}
	fmt.Println(filepath.Join(dir, "overlay.json"))
	return nil
}

// build writes the overlay of w.profile and returns its directory.
func (w *workspace) build() (string, error) {
	if err := w.needGoroot(); err != nil {
		return "", err
	}
	ps, err := w.profilePatches()
	if err != nil {
		return "", err
	}
	g := w.goroot()
	pristine := pristineFiles(ps)
	if err := checkPins(w.pinsFile(), g, w.version, pristine); err != nil {
		return "", err
	}
	out, err := w.outputDir(w.overlayDir())
	if err != nil {
		return "", err
	}
	if err := prepareOutput(out); err != nil {
		return "", err
	}
	for _, f := range pristine {
		if err := copyFile(filepath.Join(g, f), filepath.Join(out, f)); err != nil {
			return "", err
		}
	}
	if _, err := applyPatches(out, w.version, ps); err != nil {
		return "", err
	}
	replace := map[string]string{}
	for _, f := range touchedFiles(ps) {
		replace[filepath.Join(g, f)] = ""
		if _, err := os.Stat(filepath.Join(out, f)); err == nil {
			replace[filepath.Join(g, f)] = filepath.Join(out, f)
		} // else: the patches delete it
	}
	data, err := json.MarshalIndent(struct{ Replace map[string]string }{replace}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(out, "overlay.json"), append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	if err := writeStamp(out, w.version, w.profile, ps); err != nil {
		return "", err
	}
	logf("profile %s on %s: %d files", w.profile, w.version, len(replace))
	return out, nil
}

func cmdMaterialize(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	dir, err := w.materialize(w.materializedDir())
	if err != nil {
		return err
	}
	fmt.Println(dir)
	return nil
}

// materialize writes a patched copy of GOROOT with w.profile to dir.
func (w *workspace) materialize(dir string) (string, error) {
	if err := w.needGoroot(); err != nil {
		return "", err
	}
	ps, err := w.profilePatches()
	if err != nil {
		return "", err
	}
	g := w.goroot()
	if err := checkPins(w.pinsFile(), g, w.version, pristineFiles(ps)); err != nil {
		return "", err
	}
	out, err := w.outputDir(dir)
	if err != nil {
		return "", err
	}
	if err := prepareOutput(out); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(g)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if err := copyTree(filepath.Join(g, e.Name()), filepath.Join(out, e.Name())); err != nil {
			return "", err
		}
	}
	if _, err := applyPatches(out, w.version, ps); err != nil {
		return "", err
	}
	if err := writeStamp(out, w.version, w.profile, ps); err != nil {
		return "", err
	}
	if _, err := output("", goEnv(out, ""), filepath.Join(out, "bin", "go"), "version"); err != nil {
		return "", err
	}
	return out, nil
}

func cmdEnv(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	if err := w.needGoroot(); err != nil {
		return err
	}
	tags := "-tags=ivory,ivory_" + w.profile
	if w.materialized {
		dir, err := filepath.Abs(w.materializedDir())
		if err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(dir, stampFile)); err != nil {
			return fmt.Errorf("no materialized GOROOT at %s; run: ivory-overlay materialize -profile %s", dir, w.profile)
		}
		printEnv(dir, tags)
		return nil
	}
	dir, err := filepath.Abs(w.overlayDir())
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "overlay.json")); err != nil {
		return fmt.Errorf("no overlay at %s; run: ivory-overlay build -profile %s", dir, w.profile)
	}
	printEnv(w.goroot(), "-overlay="+filepath.Join(dir, "overlay.json")+" "+tags)
	return nil
}

func printEnv(goroot, goflags string) {
	fmt.Printf("export GOROOT=%s\n", shellQuote(goroot))
	fmt.Printf("export PATH=%s:\"$PATH\"\n", shellQuote(filepath.Join(goroot, "bin")))
	fmt.Printf("export GOTOOLCHAIN=local\n")
	fmt.Printf("export GOFLAGS=%s\n", shellQuote(goflags))
}

// cmdStdtest runs go test -short on crypto/x509 and crypto/tls under the
// overlay. Arguments are passed to go test before the packages.
func cmdStdtest(w *workspace, args []string) error {
	return w.stdtest(args)
}

func (w *workspace) stdtest(args []string) error {
	if err := w.needGoroot(); err != nil {
		return err
	}
	ps, err := w.profilePatches()
	if err != nil {
		return err
	}
	testArgs := append(append([]string{"test", "-short", "-count=1"}, args...), "crypto/x509", "crypto/tls")
	if changesTestdata(ps) {
		// Tests read testdata from disk, not through the overlay. A profile
		// whose patches change testdata (P6 re-records handshakes) runs in a
		// materialized GOROOT instead; -o names the overlay, not this copy.
		dir, err := w.materialize(filepath.Join(w.cache, "goroot", w.version+"-"+w.profile+"-stdtest"))
		if err != nil {
			return err
		}
		logf("profile %s changes testdata: testing the materialized GOROOT %s", w.profile, dir)
		return runIn(filepath.Join(dir, "src"), goEnv(dir, ""), filepath.Join(dir, "bin", "go"), testArgs...)
	}
	dir, err := filepath.Abs(w.overlayDir())
	if err != nil {
		return err
	}
	if ok, err := stampIsCurrent(dir, w.version, w.profile, ps); err != nil || !ok {
		return fmt.Errorf("no current overlay at %s; run: ivory-overlay build -profile %s", dir, w.profile)
	}
	g := w.goroot()
	testArgs = append([]string{testArgs[0], "-overlay=" + filepath.Join(dir, "overlay.json")}, testArgs[1:]...)
	return runIn(filepath.Join(g, "src"), goEnv(g, ""), filepath.Join(g, "bin", "go"), testArgs...)
}

func cmdBogo(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	return w.runBogo()
}

// runBogo runs BoGo in a materialized GOROOT: the runner reads
// bogo_config.json from disk, not through the overlay.
func (w *workspace) runBogo() error {
	out := w.out
	if out == "" {
		out = filepath.Join(w.cache, "goroot", w.version+"-"+w.profile+"-bogo")
	}
	dir, err := w.materialize(out)
	if err != nil {
		return err
	}
	args := []string{"test", "-count=1", "-run", "TestBogoSuite", "crypto/tls"}
	if w.filter != "" {
		// With a filter, -v lists every selected test in the log.
		args = append(args, "-v", "-args", "-bogo-filter="+w.filter)
	}
	logf("running BoGo in %s %s", dir, w.filter)
	// BoringSSL comes through the module proxy (crypto/internal/cryptotest).
	env := goEnv(dir, "")
	if os.Getenv("GOPROXY") == "" {
		env = append(env, "GOPROXY=https://proxy.golang.org")
	}
	return runIn(filepath.Join(dir, "src"), env, filepath.Join(dir, "bin", "go"), args...)
}
