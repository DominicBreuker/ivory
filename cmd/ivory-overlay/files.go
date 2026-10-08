package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func sha256File(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writePins writes the SHA-256 of each file in goroot to pinFile, in the
// format of sha256sum(1).
func writePins(pinFile, goroot string, files []string) error {
	var buf bytes.Buffer
	for _, f := range files {
		sum, err := sha256File(filepath.Join(goroot, filepath.FromSlash(f)))
		if err != nil {
			return fmt.Errorf("%s is missing from %s", f, goroot)
		}
		fmt.Fprintf(&buf, "%s  %s\n", sum, f)
	}
	if err := os.MkdirAll(filepath.Dir(pinFile), 0o755); err != nil {
		return err
	}
	tmp := pinFile + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, pinFile)
}

// readPins reads a pin file written by writePins.
func readPins(pinFile string) (map[string]string, error) {
	data, err := os.ReadFile(pinFile)
	if err != nil {
		return nil, err
	}
	pins := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		sum, f, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s: bad line %q", pinFile, sc.Text())
		}
		pins[f] = sum
	}
	return pins, nil
}

// checkPins verifies the given files of goroot against the pin file.
func checkPins(pinFile, goroot, version string, files []string) error {
	pins, err := readPins(pinFile)
	if os.IsNotExist(err) {
		return fmt.Errorf("no pins for %s (%s); run: ivory-overlay pin -go %s", version, pinFile, version)
	}
	if err != nil {
		return err
	}
	var missing []string
	for _, f := range files {
		want, ok := pins[f]
		if !ok {
			missing = append(missing, f)
			continue
		}
		got, err := sha256File(filepath.Join(goroot, filepath.FromSlash(f)))
		if err != nil {
			return fmt.Errorf("pinned file %s is missing from %s", f, goroot)
		}
		if got != want {
			return fmt.Errorf("%s does not match its pin (got %s, want %s)", filepath.Join(goroot, f), got, want)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("files not pinned for %s: %s; run: ivory-overlay pin -go %s", version, strings.Join(missing, " "), version)
	}
	return nil
}

// copyFile copies src to dst with the mode of src, creating dst's directory.
func copyFile(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm()|0o200)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyTree copies the directory src to dst, which must not exist. Files keep
// their permission bits, made writable for the owner; symbolic links are
// copied as links.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			return copyFile(p, target)
		}
	})
}

const stampFile = "IVORY-STAMP"

// prepareOutput makes dir an empty output directory. An existing dir is
// replaced only if it is empty or an earlier output of this tool (it has an
// IVORY-STAMP), so that a mistyped -o can't delete anything else. The stamp
// is written at once and completed by writeStamp, so a failed run leaves a
// directory that the next run may replace.
func prepareOutput(dir string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		if _, err := os.Stat(filepath.Join(dir, stampFile)); err != nil {
			return fmt.Errorf("refusing to replace %s: it is not empty and has no %s", dir, stampFile)
		}
		if err := makeWritable(dir); err != nil {
			return err
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stampFile), []byte("incomplete\n"), 0o644)
}

// makeWritable adds the owner's write bit to every directory under dir, so
// that RemoveAll can delete a tree copied from the read-only module cache.
func makeWritable(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return os.Chmod(p, fi.Mode().Perm()|0o700)
	})
}

// writeStamp records the Go release, the profile and the patch hashes.
func writeStamp(dir, version, profile string, ps []*patch) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "go %s\nprofile %s\n", version, profile)
	for _, p := range ps {
		fmt.Fprintf(&buf, "patch %x %s\n", sha256.Sum256(p.data), p.name)
	}
	return os.WriteFile(filepath.Join(dir, stampFile), buf.Bytes(), 0o644)
}

// stampIsCurrent reports whether the stamp in dir matches the patches as
// they are now.
func stampIsCurrent(dir, version, profile string, ps []*patch) (bool, error) {
	got, err := os.ReadFile(filepath.Join(dir, stampFile))
	if err != nil {
		return false, err
	}
	var want bytes.Buffer
	fmt.Fprintf(&want, "go %s\nprofile %s\n", version, profile)
	for _, p := range ps {
		fmt.Fprintf(&want, "patch %x %s\n", sha256.Sum256(p.data), p.name)
	}
	return bytes.Equal(got, want.Bytes()), nil
}

// An applied patch records where git apply had to move hunks.
type applied struct {
	patch   *patch
	offsets []string // "src/x.go: Hunk #1 succeeded at 78 (offset 1 line)"
}

var (
	checkingRE = regexp.MustCompile(`^Checking patch (\S+)\.\.\.$`)
	offsetRE   = regexp.MustCompile(`^Hunk #[0-9]+ succeeded at [0-9]+ \(offset -?[0-9]+ lines?\)\.$`)
	rejectedRE = regexp.MustCompile(`^Rejected hunk #[0-9]+\.$|^error: |^Applying patch \S+ with [0-9]+ reject`)
)

// gitApply applies one patch in dir with git apply, which needs exact
// context but allows hunks to move. GIT_CEILING_DIRECTORIES keeps git from
// using an enclosing repository as the base for the patch paths. With
// reject, git applies the hunks that fit and writes the others to .rej
// files.
func gitApply(dir string, p *patch, reject bool) (*applied, []string, error) {
	args := []string{"apply", "-v", "--whitespace=nowarn", "-p1"}
	if reject {
		args = append(args, "--reject")
	}
	cmd := exec.Command("git", append(args, p.path)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
	out, err := cmd.CombinedOutput()
	a := &applied{patch: p}
	var problems []string
	file := ""
	for _, line := range strings.Split(string(out), "\n") {
		if m := checkingRE.FindStringSubmatch(line); m != nil {
			file = m[1]
		}
		switch {
		case offsetRE.MatchString(line):
			a.offsets = append(a.offsets, file+": "+strings.TrimSuffix(line, "."))
		case rejectedRE.MatchString(line):
			problems = append(problems, strings.TrimPrefix(line, "error: "))
		}
	}
	if err != nil {
		if len(problems) == 0 {
			problems = []string{strings.TrimSpace(string(out))}
		}
		return a, problems, fmt.Errorf("patch %s does not apply: %s", p.name, strings.Join(problems, "; "))
	}
	return a, nil, nil
}

// applyPatches applies patches in order in dir, which holds "src/...".
func applyPatches(dir, version string, ps []*patch) ([]*applied, error) {
	var as []*applied
	for _, p := range ps {
		a, _, err := gitApply(dir, p, false)
		if err != nil {
			return nil, fmt.Errorf("%v (to %s)", err, version)
		}
		if len(a.offsets) > 0 {
			logf("applied %s with offsets: %s", p.name, strings.Join(a.offsets, "; "))
		} else {
			logf("applied %s", p.name)
		}
		as = append(as, a)
	}
	return as, nil
}
