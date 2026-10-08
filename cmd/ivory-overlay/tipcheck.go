package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func tipFlags(fs *flag.FlagSet, w *workspace) {
	profileFlags(fs, w)
	fs.StringVar(&w.remote, "remote", "https://github.com/golang/go", "Go repository to fetch")
	fs.StringVar(&w.ref, "ref", "master", "branch or tag to check")
	fs.StringVar(&w.src, "src", "", "checkout to use (default: $IVORY_CACHE/tip/go); tipcheck resets and cleans it")
	fs.BoolVar(&w.test, "test", false, "also build the patched tree (make.bash, bootstrapped by the pinned release) and run go test -short crypto/x509 crypto/tls")
}

// cmdTipcheck applies the profile's patches to the tip of Go's development
// branch, in order, and reports for each patch whether it applies as is,
// applies with moved hunks, or has hunks that don't apply. It exits with
// status 1 if a patch doesn't apply or, with -test, if the tests fail.
func cmdTipcheck(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	ps, err := w.profilePatches()
	if err != nil {
		return err
	}
	src := w.src
	if src == "" {
		src = filepath.Join(w.cache, "tip", "go")
	}
	if src, err = filepath.Abs(src); err != nil {
		return err
	}
	if err := fetchTip(src, w.remote, w.ref); err != nil {
		return err
	}
	head, err := output(src, nil, "git", "log", "-1", "--format=%H %cI")
	if err != nil {
		return err
	}
	fmt.Printf("tip:     %s %s (%s)\n", w.ref, strings.TrimSpace(head), w.remote)
	fmt.Printf("profile: %s\n", w.profile)
	failed := false
	for _, p := range ps {
		a, problems, err := gitApply(src, p, true)
		switch {
		case err != nil:
			failed = true
			fmt.Printf("FAIL     %s\n", p.name)
			for _, s := range problems {
				fmt.Printf("           %s\n", s)
			}
		case len(a.offsets) > 0:
			fmt.Printf("offsets  %s\n", p.name)
			for _, s := range a.offsets {
				fmt.Printf("           %s\n", s)
			}
		default:
			fmt.Printf("ok       %s\n", p.name)
		}
	}
	if failed {
		rej, _ := output(src, nil, "git", "ls-files", "--others", "--exclude-standard", "*.rej")
		fmt.Printf("rejected hunks are in %s:\n%s", src, rej)
		return errConflict
	}
	rws, err := readRewrites(w.tipRewritesFile())
	if err != nil {
		return err
	}
	counts, err := applyRewrites(src, ps, rws)
	if err != nil {
		return err
	}
	for i, rw := range rws {
		fmt.Printf("rewrite  %q => %q: %d\n", rw[0], rw[1], counts[i])
	}
	if !w.test {
		return nil
	}
	if err := w.needGoroot(); err != nil {
		return err
	}
	// make.bash finds GOROOT itself.
	env := environ([]string{"GOROOT", "GOFLAGS", "GOTOOLCHAIN"}, "GOROOT_BOOTSTRAP="+w.goroot(), "GOTOOLCHAIN=local")
	logf("building %s with GOROOT_BOOTSTRAP=%s", src, w.goroot())
	if err := runIn(filepath.Join(src, "src"), env, "bash", "make.bash"); err != nil {
		fmt.Printf("build:   FAIL\n")
		return err
	}
	goBin := filepath.Join(src, "bin", "go")
	if err := runIn(filepath.Join(src, "src"), goEnv(src, ""), goBin, "test", "-short", "-count=1", "crypto/x509", "crypto/tls"); err != nil {
		fmt.Printf("tests:   FAIL\n")
		return err
	}
	if err := runIn(filepath.Join(src, "src"), goEnv(src, ""), goBin, "vet", "crypto/x509", "crypto/tls"); err != nil {
		fmt.Printf("vet:     FAIL\n")
		return err
	}
	fmt.Printf("tests:   ok (go test -short, go vet: crypto/x509 crypto/tls)\n")
	return nil
}

// tipRewritesFile is the list of literal rewrites that adapt the patched
// files to changes on Go's development branch that the pinned release
// doesn't have, such as a renamed test helper. The upstream changes (CLs)
// need the same rewrites; the overlay can't have them.
func (w *workspace) tipRewritesFile() string {
	return filepath.Join(w.root, "overlay", "tip-rewrites.txt")
}

// readRewrites reads a rewrites file: one "old => new" per line, where
// \n, \t and \\ stand for a newline, a tab and a backslash; blank lines and
// lines starting with "#" are ignored. A missing file has none.
func readRewrites(file string) ([][2]string, error) {
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rws [][2]string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		old, new, ok := strings.Cut(line, " => ")
		if !ok || old == "" {
			return nil, fmt.Errorf("%s:%d: want \"old => new\"", file, i+1)
		}
		rws = append(rws, [2]string{unescape.Replace(old), unescape.Replace(new)})
	}
	return rws, nil
}

var unescape = strings.NewReplacer(`\\`, `\`, `\n`, "\n", `\t`, "\t")

// applyRewrites applies rws, in order, to every file under src that the
// patches ps write, and returns how often each rewrite was applied.
func applyRewrites(src string, ps []*patch, rws [][2]string) ([]int, error) {
	counts := make([]int, len(rws))
	if len(rws) == 0 {
		return counts, nil
	}
	seen := map[string]bool{}
	for _, p := range ps {
		for _, f := range p.new {
			if seen[f] {
				continue
			}
			seen[f] = true
			file := filepath.Join(src, filepath.FromSlash(f))
			data, err := os.ReadFile(file)
			if os.IsNotExist(err) {
				continue // deleted by a patch
			}
			if err != nil {
				return nil, err
			}
			s := string(data)
			for i, rw := range rws {
				counts[i] += strings.Count(s, rw[0])
				s = strings.ReplaceAll(s, rw[0], rw[1])
			}
			if s != string(data) {
				if err := os.WriteFile(file, []byte(s), 0o644); err != nil {
					return nil, err
				}
			}
		}
	}
	return counts, nil
}

// fetchTip makes src a clean checkout of ref from remote: a shallow clone,
// or a fetch and a hard reset of an existing one.
func fetchTip(src, remote, ref string) error {
	if _, err := os.Stat(filepath.Join(src, ".git")); err != nil {
		if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
			return err
		}
		logf("cloning %s %s into %s", remote, ref, src)
		return runIn("", nil, "git", "clone", "-q", "--depth=1", "--branch", ref, remote, src)
	}
	logf("updating %s to %s %s", src, remote, ref)
	for _, args := range [][]string{
		{"fetch", "-q", "--depth=1", remote, ref},
		{"reset", "-q", "--hard", "FETCH_HEAD"},
		{"clean", "-q", "-fdx"},
	} {
		if err := runIn(src, nil, "git", args...); err != nil {
			return err
		}
	}
	return nil
}
