package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// goVersion is a parsed Go release, "go1.27.1".
type goVersion [3]int

func parseGoVersion(s string) (goVersion, bool) {
	var v goVersion
	if !versionRE.MatchString(s) {
		return v, false
	}
	for i, f := range strings.Split(strings.TrimPrefix(s, "go"), ".") {
		v[i], _ = strconv.Atoi(f)
	}
	return v, true
}

func (v goVersion) less(u goVersion) bool {
	for i := range v {
		if v[i] != u[i] {
			return v[i] < u[i]
		}
	}
	return false
}

// toolchainReleases parses the versions of the golang.org/toolchain module
// and returns the releases (no betas or release candidates) for goos/goarch,
// oldest first.
func toolchainReleases(versions []string, goos, goarch string) []string {
	suffix := "." + goos + "-" + goarch
	var rel []string
	for _, v := range versions {
		s, ok := strings.CutPrefix(v, "v0.0.1-")
		if !ok || !strings.HasSuffix(s, suffix) {
			continue
		}
		s = strings.TrimSuffix(s, suffix)
		if _, ok := parseGoVersion(s); ok {
			rel = append(rel, s)
		}
	}
	sort.Slice(rel, func(i, j int) bool {
		a, _ := parseGoVersion(rel[i])
		b, _ := parseGoVersion(rel[j])
		return a.less(b)
	})
	return rel
}

// newestPatch returns the newest release in rel of the minor series of
// version, or version itself.
func newestPatch(rel []string, version string) string {
	v, _ := parseGoVersion(version)
	newest := version
	for _, r := range rel {
		u, _ := parseGoVersion(r)
		n, _ := parseGoVersion(newest)
		if u[0] == v[0] && u[1] == v[1] && n.less(u) {
			newest = r
		}
	}
	return newest
}

// releases lists the Go releases on the module proxy, with the go command on
// PATH (it honors GOPROXY).
func releases() ([]string, error) {
	tmp, err := os.MkdirTemp("", "ivory-latest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	out, err := output(tmp, hostGoEnv("GOFLAGS=-mod=mod"), "go", "list", "-m", "-json", "-versions", "golang.org/toolchain")
	if err != nil {
		return nil, err
	}
	var mod struct{ Versions []string }
	if err := json.Unmarshal([]byte(out), &mod); err != nil {
		return nil, err
	}
	rel := toolchainReleases(mod.Versions, runtime.GOOS, runtime.GOARCH)
	if len(rel) == 0 {
		return nil, fmt.Errorf("no Go releases for %s/%s on the module proxy", runtime.GOOS, runtime.GOARCH)
	}
	return rel, nil
}

func cmdLatest(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	rel, err := releases()
	if err != nil {
		return err
	}
	fmt.Printf("pinned %s\npatch %s\nnewest %s\n", w.version, newestPatch(rel, w.version), rel[len(rel)-1])
	return nil
}

func adoptFlags(fs *flag.FlagSet, w *workspace) {
	goFlags(fs, w)
	fs.BoolVar(&w.bogo, "bogo", true, "run the full BoGo suite for every profile")
	fs.BoolVar(&w.test, "test", true, "run the test suite after the update")
	fs.BoolVar(&w.force, "force", false, "allow uncommitted changes in overlay/ and README.md")
}

// cmdAdopt moves the module to a new Go release (-go, default: the newest
// patch release of the pinned one): it fetches the release, applies every
// patch to it, rebases the patches whose hunks moved, writes the new pins and
// overlay/GOVERSION, updates README.md, and runs the test suite for every
// profile. It changes files in the module but commits nothing.
func cmdAdopt(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	start := time.Now()
	pinned, err := w.pinnedVersion()
	if err != nil {
		return err
	}
	if w.version == pinned {
		rel, err := releases()
		if err != nil {
			return err
		}
		w.version = newestPatch(rel, pinned)
		if w.version == pinned {
			fmt.Printf("%s is the newest patch release; nothing to adopt\n", pinned)
			return nil
		}
	}
	from, _ := parseGoVersion(pinned)
	to, _ := parseGoVersion(w.version)
	if to.less(from) {
		return fmt.Errorf("%s is older than the pinned %s", w.version, pinned)
	}
	if !w.force {
		dirty, err := output(w.root, nil, "git", "status", "--porcelain", "--", "overlay", "README.md")
		if err != nil {
			return err
		}
		if dirty != "" {
			return fmt.Errorf("uncommitted changes in overlay/ or README.md (use -force):\n%s", dirty)
		}
	}
	logf("adopting %s (pinned: %s)", w.version, pinned)
	if err := w.fetchToolchain(); err != nil {
		return err
	}
	ps, err := w.allPatches()
	if err != nil {
		return err
	}

	// Which pinned files changed?
	oldPins, err := readPins(filepath.Join(w.root, "overlay", "pins", pinned+".sha256"))
	if err != nil {
		return err
	}
	var changed []string
	for _, f := range pristineFiles(ps) {
		sum, err := sha256File(filepath.Join(w.goroot(), f))
		if err != nil {
			return fmt.Errorf("%s: %s is missing; the patches need rework", w.version, f)
		}
		if oldPins[f] != sum {
			changed = append(changed, f)
		}
	}
	fmt.Printf("%d of %d patched files changed from %s to %s\n", len(changed), len(oldPins), pinned, w.version)
	for _, f := range changed {
		fmt.Printf("  %s\n", f)
	}

	rebased, err := rebase(filepath.Join(w.cache, "adopt", w.version), w.goroot(), w.version, ps, false)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if !bytes.Equal(rebased[p.name], p.data) {
			if err := os.WriteFile(p.path, rebased[p.name], 0o644); err != nil {
				return err
			}
		}
	}
	if ps, err = w.allPatches(); err != nil {
		return err
	}
	if err := writePins(w.pinsFile(), w.goroot(), pristineFiles(ps)); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(w.root, "overlay", "pins", pinned+".sha256")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(w.root, "overlay", "GOVERSION"), []byte(w.version+"\n"), 0o644); err != nil {
		return err
	}
	if err := replaceInFile(filepath.Join(w.root, "README.md"), "| "+pinned+" |", "| "+w.version+" |"); err != nil {
		logf("README.md: %v; update the supported Go versions by hand", err)
	}
	fmt.Printf("updated overlay/patches, overlay/pins/%s.sha256, overlay/GOVERSION, README.md (%s)\n",
		w.version, time.Since(start).Round(time.Second))

	if w.test {
		if err := w.testSuite(); err != nil {
			fmt.Printf("\nThe test suite failed on %s. The files are updated but not committed;\n"+
				"fix the patches (overlay/README.md) or revert with git checkout.\n", w.version)
			return err
		}
	}
	fmt.Printf("\nAdopted %s in %s. Next:\n", w.version, time.Since(start).Round(time.Second))
	fmt.Printf("  git add -A overlay README.md && git commit -m 'Adopt %s'\n", w.version)
	fmt.Printf("  push, wait for CI, merge, and tag the release\n")
	// Hints only: the files a user reads (top-level and docs/*.md, the
	// overlay README, workflows, scripts). Records in subdirectories of
	// docs/ name old releases on purpose.
	if refs, err := output(w.root, nil, "git", "grep", "-l", "-F", pinned, "--",
		":(glob)*.md", ":(glob)docs/*.md", "overlay/README.md", ".github", "scripts"); err == nil && refs != "" {
		fmt.Printf("  check these files, which still name %s:\n", pinned)
		for _, f := range strings.Fields(refs) {
			fmt.Printf("    %s\n", f)
		}
	}
	return nil
}

func replaceInFile(file, old, new string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte(old)) {
		return fmt.Errorf("no %q", old)
	}
	return os.WriteFile(file, bytes.Replace(data, []byte(old), []byte(new), 1), 0o644)
}

// testSuite builds every profile and runs Go's tests under it, then the
// module's own vet and tests, with and without the overlay.
func (w *workspace) testSuite() error {
	profiles, err := w.profiles()
	if err != nil {
		return err
	}
	type step struct {
		name string
		f    func() error
	}
	var steps []step
	for _, prof := range profiles {
		pw := *w
		pw.profile, pw.out = prof, ""
		steps = append(steps,
			step{"build " + prof, func() error { _, err := pw.build(); return err }},
			step{"stdtest " + prof, func() error { return pw.stdtest(nil) }},
			step{"vet and test ./... " + prof, func() error {
				goflags := "-overlay=" + filepath.Join(pw.overlayDir(), "overlay.json") + " -tags=ivory,ivory_" + prof
				return w.moduleTests(goflags)
			}},
		)
		if w.bogo {
			steps = append(steps, step{"bogo " + prof, pw.runBogo})
		}
	}
	steps = append(steps,
		step{"vet and test ./... stock", func() error { return w.moduleTests("") }},
		step{"vet and test cmd/ivory-overlay", func() error {
			dir := filepath.Join(w.root, "cmd", "ivory-overlay")
			goBin := filepath.Join(w.goroot(), "bin", "go")
			if err := runIn(dir, goEnv(w.goroot(), ""), goBin, "vet", "./..."); err != nil {
				return err
			}
			return runIn(dir, goEnv(w.goroot(), ""), goBin, "test", "-count=1", "./...")
		}},
	)
	for _, s := range steps {
		t := time.Now()
		logf("%s", s.name)
		if err := s.f(); err != nil {
			fmt.Printf("FAIL  %s: %v\n", s.name, err)
			return err
		}
		fmt.Printf("ok    %s (%s)\n", s.name, time.Since(t).Round(time.Second))
	}
	return nil
}

// moduleTests runs go vet and go test on the ivory module.
func (w *workspace) moduleTests(goflags string) error {
	env := goEnv(w.goroot(), goflags)
	goBin := filepath.Join(w.goroot(), "bin", "go")
	if err := runIn(w.root, env, goBin, "vet", "./..."); err != nil {
		return err
	}
	return runIn(w.root, env, goBin, "test", "-count=1", "./...")
}

// rebase applies the patches, in order, to the pristine files of the
// toolchain in goroot, in a scratch git repository, and returns the new
// content of each patch file: the Base note in its description set to
// version, and its diff exported again (git diff without index lines) where
// git apply had to move hunks, or for every patch if export is set. Patches
// that apply exactly keep their diff byte for byte.
func rebase(scratch, goroot, version string, ps []*patch, export bool) (map[string][]byte, error) {
	if err := prepareOutput(scratch); err != nil {
		return nil, err
	}
	for _, f := range pristineFiles(ps) {
		if err := copyFile(filepath.Join(goroot, f), filepath.Join(scratch, f)); err != nil {
			return nil, err
		}
	}
	git := func(args ...string) (string, error) {
		return output(scratch, append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(scratch)), "git",
			append([]string{"-c", "user.name=ivory-overlay", "-c", "user.email=ivory-overlay@invalid",
				"-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"}, args...)...)
	}
	if _, err := git("init", "-q"); err != nil {
		return nil, err
	}
	if _, err := git("add", "src"); err != nil {
		return nil, err
	}
	if _, err := git("commit", "-q", "--no-verify", "-m", "pristine "+version); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, p := range ps {
		a, problems, err := gitApply(scratch, p, false)
		if err != nil {
			return nil, fmt.Errorf("%s doesn't apply to %s; rebase it by hand (overlay/README.md):\n  %s",
				p.name, version, strings.Join(problems, "\n  "))
		}
		if _, err := git("add", "-A", "src"); err != nil {
			return nil, err
		}
		if _, err := git("commit", "-q", "--no-verify", "-m", p.name); err != nil {
			return nil, err
		}
		body := p.body
		if len(a.offsets) > 0 || export {
			diff, err := git("-c", "core.quotePath=false", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
				"-c", "diff.relative=false", "-c", "diff.renames=false",
				"diff", "--no-color", "--no-ext-diff", "--no-textconv", "HEAD~1", "HEAD")
			if err != nil {
				return nil, err
			}
			body = dropIndexLines(diff)
			if len(a.offsets) > 0 {
				logf("rebased %s: %s", p.name, strings.Join(a.offsets, "; "))
			}
		}
		out[p.name] = p.withBase(version, body)
	}
	return out, nil
}

// dropIndexLines removes the "index <hash>..<hash>" lines of git diff, which
// name blobs of the scratch repository.
func dropIndexLines(diff string) []byte {
	var b bytes.Buffer
	for _, line := range strings.SplitAfter(diff, "\n") {
		if !strings.HasPrefix(line, "index ") {
			b.WriteString(line)
		}
	}
	return b.Bytes()
}
