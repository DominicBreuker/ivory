package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// A workspace is the ivory module the tool works on, the cache, and the
// flags of the command.
type workspace struct {
	root  string // the ivory module, absolute
	cache string // $IVORY_CACHE, absolute

	version      string // Go release, "go1.27.1"
	profile      string
	out          string // -o
	materialized bool   // env, doctor: -materialized
	filter       string // bogo: -filter

	// tipcheck and adopt flags.
	src, remote, ref string
	test, bogo       bool
	force            bool
}

var versionRE = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)

func (w *workspace) init() error {
	if w.root == "" {
		w.root = os.Getenv("IVORY_ROOT")
	}
	if w.root == "" {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		if w.root, err = findRoot(dir); err != nil {
			return err
		}
	}
	var err error
	if w.root, err = filepath.Abs(w.root); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(w.root, "overlay", "GOVERSION")); err != nil {
		return fmt.Errorf("%s is not an ivory module: %v", w.root, err)
	}
	w.cache = os.Getenv("IVORY_CACHE")
	if w.cache == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("no IVORY_CACHE and no home directory: %v", err)
		}
		w.cache = filepath.Join(home, ".cache", "ivory")
	}
	if w.cache, err = filepath.Abs(w.cache); err != nil {
		return err
	}
	if w.version == "" {
		if w.version, err = w.pinnedVersion(); err != nil {
			return err
		}
	}
	if !versionRE.MatchString(w.version) {
		return fmt.Errorf("bad Go version %q (want a release such as go1.27.1)", w.version)
	}
	return nil
}

// findRoot returns the first directory, from dir upwards, that holds
// overlay/GOVERSION.
func findRoot(dir string) (string, error) {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, "overlay", "GOVERSION")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no ivory module in %s or its parents (no overlay/GOVERSION); use -root or IVORY_ROOT", dir)
		}
		d = parent
	}
}

// pinnedVersion reads overlay/GOVERSION.
func (w *workspace) pinnedVersion() (string, error) {
	b, err := os.ReadFile(filepath.Join(w.root, "overlay", "GOVERSION"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (w *workspace) patchesDir() string  { return filepath.Join(w.root, "overlay", "patches") }
func (w *workspace) profilesDir() string { return filepath.Join(w.root, "overlay", "profiles") }
func (w *workspace) pinsFile() string {
	return filepath.Join(w.root, "overlay", "pins", w.version+".sha256")
}

// goroot is the pristine toolchain of w.version.
func (w *workspace) goroot() string { return filepath.Join(w.cache, w.version) }

func (w *workspace) overlayDir() string {
	if w.out != "" {
		return w.out
	}
	return filepath.Join(w.cache, "overlay", w.version+"-"+w.profile)
}

func (w *workspace) materializedDir() string {
	if w.out != "" {
		return w.out
	}
	return filepath.Join(w.cache, "goroot", w.version+"-"+w.profile)
}

func (w *workspace) needGoroot() error {
	if _, err := os.Stat(filepath.Join(w.goroot(), "bin", "go")); err != nil {
		return fmt.Errorf("no toolchain at %s; run: ivory-overlay toolchain -go %s", w.goroot(), w.version)
	}
	return nil
}

// profiles lists the profile names in overlay/profiles.
func (w *workspace) profiles() ([]string, error) {
	m, err := filepath.Glob(filepath.Join(w.profilesDir(), "*.txt"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, f := range m {
		names = append(names, strings.TrimSuffix(filepath.Base(f), ".txt"))
	}
	sort.Strings(names)
	return names, nil
}

// profilePatches reads the patches of w.profile, in order.
func (w *workspace) profilePatches() ([]*patch, error) {
	f := filepath.Join(w.profilesDir(), w.profile+".txt")
	data, err := os.ReadFile(f)
	if err != nil {
		names, _ := w.profiles()
		return nil, fmt.Errorf("no profile %s (want one of: %s)", w.profile, strings.Join(names, " "))
	}
	var ps []*patch
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line != filepath.Base(line) {
			return nil, fmt.Errorf("profile %s: %q is not a file name in overlay/patches", w.profile, line)
		}
		p, err := readPatch(filepath.Join(w.patchesDir(), line))
		if err != nil {
			return nil, fmt.Errorf("profile %s: %v", w.profile, err)
		}
		ps = append(ps, p)
	}
	if len(ps) == 0 {
		return nil, fmt.Errorf("profile %s lists no patches", w.profile)
	}
	return ps, nil
}

// allPatches reads every patch in overlay/patches, in file name order. The
// numbers in the names give the order in which the patches stack.
func (w *workspace) allPatches() ([]*patch, error) {
	m, err := filepath.Glob(filepath.Join(w.patchesDir(), "*.patch"))
	if err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("no patches in %s", w.patchesDir())
	}
	sort.Strings(m)
	var ps []*patch
	for _, f := range m {
		p, err := readPatch(f)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// changesTestdata reports whether a patch changes a testdata file. Tests read
// testdata from disk, not through the overlay.
func changesTestdata(ps []*patch) bool {
	for _, f := range touchedFiles(ps) {
		if strings.Contains(f, "/testdata/") {
			return true
		}
	}
	return false
}

// goEnv returns the environment for running the go command of goroot: GOROOT,
// PATH, GOTOOLCHAIN=local and the given GOFLAGS, followed by extra.
func goEnv(goroot, goflags string, extra ...string) []string {
	return environ([]string{"GOROOT", "GOTOOLCHAIN", "GOFLAGS", "PATH"}, append([]string{
		"GOROOT=" + goroot,
		"PATH=" + filepath.Join(goroot, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GOTOOLCHAIN=local",
		"GOFLAGS=" + goflags,
	}, extra...)...)
}

// environ returns the environment without the variables in drop, followed
// by extra.
func environ(drop []string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(drop, k) {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// runIn runs a command in dir with its output on standard error, so that
// standard output keeps only the results of the tool.
func runIn(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}

// output runs a command in dir and returns its standard output.
func output(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.Bytes())
	}
	return string(out), nil
}
