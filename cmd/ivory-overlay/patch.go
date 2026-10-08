package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A patch is one file in overlay/patches: a description in the style of a
// commit message, followed by a unified diff with paths "a/src/..." and
// "b/src/..." relative to GOROOT.
type patch struct {
	name   string // file name
	path   string // absolute path of the file
	data   []byte
	header []byte // the description, up to the first "diff --git" or "---" line
	body   []byte // the diff
	old    []string
	new    []string
}

// readPatch reads and parses a patch file.
func readPatch(file string) (*patch, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	p, err := parsePatch(filepath.Base(file), data)
	if err != nil {
		return nil, err
	}
	p.path, err = filepath.Abs(file)
	return p, err
}

var hunkRE = regexp.MustCompile(`^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@`)

// parsePatch splits a patch into description and diff, and collects the files
// it reads ("--- a/...") and writes ("+++ b/..."). It follows the hunk line
// counts, so that a removed line that starts with "-- " is not taken for a
// file header.
func parsePatch(name string, data []byte) (*patch, error) {
	p := &patch{name: name, data: data}
	oldSet, newSet := map[string]bool{}, map[string]bool{}
	bodyStart := -1
	oldLeft, newLeft := 0, 0 // lines left in the current hunk
	off := 0
	for lineNo := 1; off < len(data); lineNo++ {
		end := bytes.IndexByte(data[off:], '\n')
		if end < 0 {
			end = len(data) - off
		} else {
			end++
		}
		line := string(data[off : off+end])
		start := off
		off += end
		line = strings.TrimSuffix(line, "\n")
		if oldLeft > 0 || newLeft > 0 {
			switch {
			case strings.HasPrefix(line, " ") || line == "":
				oldLeft--
				newLeft--
			case strings.HasPrefix(line, "-"):
				oldLeft--
			case strings.HasPrefix(line, "+"):
				newLeft--
			case strings.HasPrefix(line, `\`): // "\ No newline at end of file"
			default:
				return nil, fmt.Errorf("%s:%d: unexpected line in hunk: %q", name, lineNo, line)
			}
			if oldLeft < 0 || newLeft < 0 {
				return nil, fmt.Errorf("%s:%d: hunk longer than its header says", name, lineNo)
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if bodyStart < 0 {
				bodyStart = start
			}
		case strings.HasPrefix(line, "--- "):
			if bodyStart < 0 {
				bodyStart = start
			}
			if f, ok := diffPath(line[4:], "a/"); ok {
				if err := checkPath(f); err != nil {
					return nil, fmt.Errorf("%s:%d: %v", name, lineNo, err)
				}
				oldSet[f] = true
			}
		case strings.HasPrefix(line, "+++ "):
			if bodyStart < 0 {
				return nil, fmt.Errorf("%s:%d: +++ line before ---", name, lineNo)
			}
			if f, ok := diffPath(line[4:], "b/"); ok {
				if err := checkPath(f); err != nil {
					return nil, fmt.Errorf("%s:%d: %v", name, lineNo, err)
				}
				newSet[f] = true
			}
		case strings.HasPrefix(line, "@@ "):
			m := hunkRE.FindStringSubmatch(line)
			if m == nil || bodyStart < 0 {
				return nil, fmt.Errorf("%s:%d: bad hunk header %q", name, lineNo, line)
			}
			oldLeft, newLeft = hunkCount(m[1]), hunkCount(m[2])
		case bodyStart >= 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-")):
			return nil, fmt.Errorf("%s:%d: diff line outside a hunk: %q", name, lineNo, line)
		}
	}
	if oldLeft > 0 || newLeft > 0 {
		return nil, fmt.Errorf("%s: last hunk is truncated", name)
	}
	if bodyStart < 0 || len(oldSet)+len(newSet) == 0 {
		return nil, fmt.Errorf("%s: no diff", name)
	}
	p.header, p.body = data[:bodyStart], data[bodyStart:]
	p.old, p.new = sortedKeys(oldSet), sortedKeys(newSet)
	return p, nil
}

func hunkCount(s string) int {
	if s == "" {
		return 1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// diffPath returns the file of a "---" or "+++" line, without its prefix;
// ok is false for /dev/null.
func diffPath(s, prefix string) (string, bool) {
	s, _, _ = strings.Cut(s, "\t") // diff(1) appends a time stamp
	if s == "/dev/null" {
		return "", false
	}
	return strings.TrimPrefix(s, prefix), true
}

// checkPath rejects paths that could escape GOROOT or that the overlay can't
// name: a patch may only touch clean relative paths under src/.
func checkPath(f string) error {
	if !strings.HasPrefix(f, "src/") {
		return fmt.Errorf("patch path %s is outside src/", f)
	}
	if path.Clean(f) != f || strings.ContainsAny(f, "\"\\ \t") {
		return fmt.Errorf("unsafe patch path %q", f)
	}
	for _, elem := range strings.Split(f, "/") {
		if elem == ".." || elem == "." {
			return fmt.Errorf("unsafe patch path %q", f)
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// pristineFiles returns the files the patches expect in GOROOT, sorted.
func pristineFiles(ps []*patch) []string {
	set := map[string]bool{}
	for _, p := range ps {
		for _, f := range p.old {
			set[f] = true
		}
	}
	return sortedKeys(set)
}

// touchedFiles returns the files the patches read, change, add or delete,
// sorted: the files the overlay replaces.
func touchedFiles(ps []*patch) []string {
	set := map[string]bool{}
	for _, p := range ps {
		for _, f := range p.old {
			set[f] = true
		}
		for _, f := range p.new {
			set[f] = true
		}
	}
	return sortedKeys(set)
}

var baseRE = regexp.MustCompile(`Base: go[0-9]+\.[0-9]+\.[0-9]+`)

// withBase returns the patch with the Go release in its description's "Base:"
// note set to version, and with body as its diff.
func (p *patch) withBase(version string, body []byte) []byte {
	header := baseRE.ReplaceAll(p.header, []byte("Base: "+version))
	return append(append([]byte{}, header...), body...)
}
