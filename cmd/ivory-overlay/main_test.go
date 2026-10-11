package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const testPatch = `pkg: change A and add b.go

A removed line that starts with "-- a/" must not count as a file header.

Base: go1.99.1.

diff --git a/src/pkg/a.go b/src/pkg/a.go
--- a/src/pkg/a.go
+++ b/src/pkg/a.go
@@ -2,4 +2,4 @@
 package a

--- a/fake
+// changed
 func A() int { return 1 }
diff --git a/src/pkg/b.go b/src/pkg/b.go
new file mode 100644
--- /dev/null
+++ b/src/pkg/b.go
@@ -0,0 +1 @@
+package a
`

const testA = "// Package a.\npackage a\n\n-- a/fake\nfunc A() int { return 1 }\n"

func TestParsePatch(t *testing.T) {
	p, err := parsePatch("t.patch", []byte(testPatch))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"src/pkg/a.go"}; !slices.Equal(p.old, want) {
		t.Errorf("old = %q, want %q", p.old, want)
	}
	if want := []string{"src/pkg/a.go", "src/pkg/b.go"}; !slices.Equal(p.new, want) {
		t.Errorf("new = %q, want %q", p.new, want)
	}
	if !strings.HasSuffix(string(p.header), "Base: go1.99.1.\n\n") || !strings.HasPrefix(string(p.body), "diff --git") {
		t.Errorf("bad split: header %q", p.header)
	}
	got := string(p.withBase("go1.99.2", p.body))
	if want := strings.Replace(testPatch, "Base: go1.99.1", "Base: go1.99.2", 1); got != want {
		t.Errorf("withBase:\n%s\nwant:\n%s", got, want)
	}
}

func TestParsePatchErrors(t *testing.T) {
	diff := "--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-a\n+b\n"
	for _, f := range []string{"README", "src/../etc/passwd", "src/./a.go", "src/a b.go", `src/a"b.go`, "src//a.go"} {
		data := strings.ReplaceAll(diff, "%s", f)
		if _, err := parsePatch("t.patch", []byte(data)); err == nil {
			t.Errorf("path %q: no error", f)
		}
	}
	for name, data := range map[string]string{
		"no diff":   "just a description\n",
		"truncated": "--- a/src/a.go\n+++ b/src/a.go\n@@ -1,2 +1,2 @@\n a\n",
		"too long":  "--- a/src/a.go\n+++ b/src/a.go\n@@ -1 +1 @@\n-a\n+b\n+c\n",
		"bad hunk":  "--- a/src/a.go\n+++ b/src/a.go\n@@ nonsense @@\n",
	} {
		if _, err := parsePatch("t.patch", []byte(data)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestPristineFiles checks that a file an earlier patch adds is not expected
// in GOROOT when a later patch changes it.
func TestPristineFiles(t *testing.T) {
	first, err := parsePatch("0000-a.patch", []byte(testPatch))
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsePatch("0100-b.patch", []byte("--- a/src/pkg/b.go\n+++ b/src/pkg/b.go\n@@ -1 +1 @@\n-package a\n+package b\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pristineFiles([]*patch{first, second}), []string{"src/pkg/a.go"}; !slices.Equal(got, want) {
		t.Errorf("pristineFiles = %q, want %q", got, want)
	}
	if got, want := pristineFiles([]*patch{second, first}), []string{"src/pkg/a.go", "src/pkg/b.go"}; !slices.Equal(got, want) {
		t.Errorf("pristineFiles in reverse order = %q, want %q", got, want)
	}
}

// TestRealPatches parses the module's patches and compares the files with
// what a line-based scan finds ("--- a/" and "+++ b/" lines).
func TestRealPatches(t *testing.T) {
	files, _ := filepath.Glob("../../overlay/patches/*.patch")
	if len(files) == 0 {
		t.Skip("no patches")
	}
	oldRE := regexp.MustCompile(`(?m)^--- a/(\S+)`)
	newRE := regexp.MustCompile(`(?m)^\+\+\+ b/(\S+)`)
	scan := func(re *regexp.Regexp, data []byte) []string {
		set := map[string]bool{}
		for _, m := range re.FindAllSubmatch(data, -1) {
			set[string(m[1])] = true
		}
		return sortedKeys(set)
	}
	for _, f := range files {
		p, err := readPatch(f)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(p.old, scan(oldRE, p.data)) || !slices.Equal(p.new, scan(newRE, p.data)) {
			t.Errorf("%s: old %q new %q differ from a line scan", p.name, p.old, p.new)
		}
		if !baseRE.Match(p.header) {
			t.Errorf("%s: no Base note in the description", p.name)
		}
	}
}

// testWorkspace makes an ivory module with testPatch in profile core, and a
// fake toolchain go1.99.1 in the cache.
func testWorkspace(t *testing.T) *workspace {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root, cache := t.TempDir(), t.TempDir()
	write := func(f, data string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "overlay", "GOVERSION"), "go1.99.1\n", 0o644)
	write(filepath.Join(root, "overlay", "patches", "0000-a.patch"), testPatch, 0o644)
	write(filepath.Join(root, "overlay", "profiles", "core.txt"), "# comment\n0000-a.patch # P0\n", 0o644)
	g := filepath.Join(cache, "go1.99.1")
	write(filepath.Join(g, "src", "pkg", "a.go"), testA, 0o644)
	write(filepath.Join(g, "bin", "go"), "#!/bin/sh\necho go version go1.99.1 linux/amd64\n", 0o755)
	t.Setenv("IVORY_CACHE", cache)
	t.Setenv("IVORY_ROOT", "")
	w := &workspace{root: root, profile: "core"}
	if err := w.init(); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestBuildAndMaterialize(t *testing.T) {
	w := testWorkspace(t)
	if _, err := w.build(); err == nil || !strings.Contains(err.Error(), "no pins") {
		t.Fatalf("build without pins: %v", err)
	}
	if err := cmdPin(w, nil); err != nil {
		t.Fatal(err)
	}
	dir, err := w.build()
	if err != nil {
		t.Fatal(err)
	}
	var ov struct{ Replace map[string]string }
	data, _ := os.ReadFile(filepath.Join(dir, "overlay.json"))
	if err := json.Unmarshal(data, &ov); err != nil {
		t.Fatal(err)
	}
	g := w.goroot()
	if len(ov.Replace) != 2 || ov.Replace[filepath.Join(g, "src/pkg/a.go")] != filepath.Join(dir, "src/pkg/a.go") ||
		ov.Replace[filepath.Join(g, "src/pkg/b.go")] != filepath.Join(dir, "src/pkg/b.go") {
		t.Errorf("overlay.json = %v", ov.Replace)
	}
	if a, _ := os.ReadFile(filepath.Join(dir, "src/pkg/a.go")); !bytes.Contains(a, []byte("// changed")) {
		t.Errorf("a.go not patched:\n%s", a)
	}
	ps, _ := w.profilePatches()
	if ok, err := stampIsCurrent(dir, w.version, w.profile, ps); !ok || err != nil {
		t.Errorf("stamp not current: %v", err)
	}

	m, err := w.materialize(filepath.Join(t.TempDir(), "goroot"))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(m, "src/pkg/b.go")); err != nil || string(b) != "package a\n" {
		t.Errorf("materialized b.go = %q, %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(m, "bin/go")); err != nil || fi.Mode()&0o100 == 0 {
		t.Errorf("materialized bin/go is not executable: %v", err)
	}

	// A changed pristine file fails the pin check.
	if err := os.WriteFile(filepath.Join(g, "src/pkg/a.go"), []byte(testA+"// local edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.build(); err == nil || !strings.Contains(err.Error(), "does not match its pin") {
		t.Errorf("build with a changed file: %v", err)
	}
}

func TestOutputSafety(t *testing.T) {
	w := testWorkspace(t)
	if err := cmdPin(w, nil); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreign, "precious"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.out = foreign
	if _, err := w.build(); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Errorf("build into a foreign directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(foreign, "precious")); err != nil {
		t.Errorf("foreign file deleted: %v", err)
	}
	for _, out := range []string{w.goroot(), filepath.Join(w.goroot(), "src"), filepath.Dir(w.root)} {
		w.out = out
		if _, err := w.build(); err == nil || !strings.Contains(err.Error(), "must be outside") {
			t.Errorf("build -o %s: %v", out, err)
		}
	}
	// An earlier output is replaced.
	w.out = filepath.Join(t.TempDir(), "ov")
	for range 2 {
		if _, err := w.build(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRebase(t *testing.T) {
	w := testWorkspace(t)
	ps, err := w.allPatches()
	if err != nil {
		t.Fatal(err)
	}
	// go1.99.2 adds two lines above the patched ones: the hunk moves.
	g2 := filepath.Join(t.TempDir(), "go1.99.2")
	if err := os.MkdirAll(filepath.Join(g2, "src", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g2, "src/pkg/a.go"), []byte("// Copyright\n\n"+testA), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := rebase(filepath.Join(t.TempDir(), "scratch"), g2, "go1.99.2", ps, false)
	if err != nil {
		t.Fatal(err)
	}
	np, err := parsePatch("0000-a.patch", out["0000-a.patch"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(np.header), "Base: go1.99.2.") || !strings.Contains(string(np.body), "@@ -3,5 +3,5 @@") ||
		strings.Contains(string(np.body), "\nindex ") {
		t.Errorf("rebased patch:\n%s", out["0000-a.patch"])
	}
	// The rebased patch applies without offsets.
	np.path = filepath.Join(t.TempDir(), "rebased.patch")
	if err := os.WriteFile(np.path, np.data, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, err := gitApply(g2, np, false)
	if err != nil || len(a.offsets) > 0 {
		t.Errorf("rebased patch: offsets %q, %v", a.offsets, err)
	}

	// A patch that applies exactly keeps its diff.
	out, err = rebase(filepath.Join(t.TempDir(), "scratch"), w.goroot(), "go1.99.3", ps, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(testPatch, "go1.99.1", "go1.99.3", 1); string(out["0000-a.patch"]) != want {
		t.Errorf("exact patch changed:\n%s", out["0000-a.patch"])
	}

	// A patch that doesn't apply is an error.
	if err := os.WriteFile(filepath.Join(g2, "src/pkg/a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rebase(filepath.Join(t.TempDir(), "scratch"), g2, "go1.99.2", ps, false); err == nil ||
		!strings.Contains(err.Error(), "rebase it by hand") {
		t.Errorf("rebase onto a conflicting file: %v", err)
	}
}

// pinnedToolchain returns the module's pinned toolchain in the cache, or
// skips the test.
func pinnedToolchain(t *testing.T) *workspace {
	t.Helper()
	w := &workspace{root: "../..", profile: "core"}
	if err := w.init(); err != nil {
		t.Skip(err)
	}
	if err := w.needGoroot(); err != nil {
		t.Skip(err)
	}
	return w
}

// TestRebaseReproducesPatches exports every patch again on the pinned
// release. The patches were made the same way (git diff without index
// lines), so the diffs must come out byte for byte; only P0 is written by
// hand.
func TestRebaseReproducesPatches(t *testing.T) {
	w := pinnedToolchain(t)
	ps, err := w.allPatches()
	if err != nil {
		t.Fatal(err)
	}
	out, err := rebase(filepath.Join(t.TempDir(), "scratch"), w.goroot(), w.version, ps, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if strings.HasPrefix(p.name, "0000-") {
			continue
		}
		if !bytes.Equal(out[p.name], p.data) {
			t.Errorf("%s: the exported patch differs", p.name)
		}
	}
}

// TestDoctorProgramFailsOnStock checks that the check program notices a
// toolchain without the patches.
func TestDoctorProgramFailsOnStock(t *testing.T) {
	w := pinnedToolchain(t)
	ps, err := w.profilePatches()
	if err != nil {
		t.Fatal(err)
	}
	out, err := runDoctorProgram(w, w.goroot(), "", ps)
	if err == nil || !strings.Contains(out, "VerifyUnsupportedSignature") {
		t.Errorf("check program on a stock toolchain: %v\n%s", err, out)
	}
}

func TestToolchainReleases(t *testing.T) {
	versions := []string{
		"v0.0.1-go1.27.1.linux-amd64", "v0.0.1-go1.27.10.linux-amd64", "v0.0.1-go1.27.2.linux-amd64",
		"v0.0.1-go1.28rc1.linux-amd64", "v0.0.1-go1.26.9.linux-amd64", "v0.0.1-go1.27.3.darwin-arm64",
		"v0.0.1-go1.28.0.linux-amd64",
	}
	rel := toolchainReleases(versions, "linux", "amd64")
	if want := []string{"go1.26.9", "go1.27.1", "go1.27.2", "go1.27.10", "go1.28.0"}; !slices.Equal(rel, want) {
		t.Errorf("releases = %q, want %q", rel, want)
	}
	if got := newestPatch(rel, "go1.27.1"); got != "go1.27.10" {
		t.Errorf("newestPatch(go1.27.1) = %s", got)
	}
	if got := newestPatch(rel, "go1.28.0"); got != "go1.28.0" {
		t.Errorf("newestPatch(go1.28.0) = %s", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote(`/a b/it's`), `'/a b/it'\''s'`; got != want {
		t.Errorf("shellQuote = %s, want %s", got, want)
	}
}

func TestRunUsage(t *testing.T) {
	var buf bytes.Buffer
	if code := run(nil, &buf); code != 2 || !strings.Contains(buf.String(), "tipcheck") {
		t.Errorf("run() = %d\n%s", code, buf.String())
	}
	buf.Reset()
	if code := run([]string{"nonsense"}, &buf); code != 2 {
		t.Errorf("run(nonsense) = %d", code)
	}
	buf.Reset()
	if code := run([]string{"build", "-go", "1.27"}, &buf); code != 1 || !strings.Contains(buf.String(), "bad Go version") {
		t.Errorf("run(build -go 1.27) = %d\n%s", code, buf.String())
	}
}

func TestRewrites(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tip-rewrites.txt")
	if rws, err := readRewrites(file); err != nil || rws != nil {
		t.Fatalf("missing file: %v, %v", rws, err)
	}
	os.WriteFile(file, []byte("# comment\n\nfunc A() => func B()\n{ return 1 }\\n => { return 2 } // \\\\n\\n\n"), 0o644)
	rws, err := readRewrites(file)
	if err != nil || len(rws) != 2 || rws[0] != [2]string{"func A()", "func B()"} || rws[1] != [2]string{"{ return 1 }\n", "{ return 2 } // \\n\n"} {
		t.Fatalf("rewrites = %q, %v", rws, err)
	}
	os.WriteFile(file, []byte("no arrow\n"), 0o644)
	if _, err := readRewrites(file); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Errorf("bad line: err = %v", err)
	}

	p, err := parsePatch("t.patch", []byte(testPatch))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "go")
	os.MkdirAll(filepath.Join(src, "src", "pkg"), 0o755)
	os.WriteFile(filepath.Join(src, "src", "pkg", "a.go"), []byte(testA), 0o644)
	other := filepath.Join(src, "src", "pkg", "c.go") // not in the patch
	os.WriteFile(other, []byte(testA), 0o644)
	counts, err := applyRewrites(src, []*patch{p}, rws) // b.go doesn't exist
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(counts, []int{1, 1}) {
		t.Errorf("counts = %v, want [1 1]", counts)
	}
	if b, _ := os.ReadFile(filepath.Join(src, "src", "pkg", "a.go")); !strings.Contains(string(b), "func B() int { return 2 } // \\n\n") {
		t.Errorf("a.go = %q", b)
	}
	if b, _ := os.ReadFile(other); string(b) != testA {
		t.Errorf("a file outside the patch changed: %q", b)
	}
}
