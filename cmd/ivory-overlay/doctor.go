package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func cmdDoctor(w *workspace, args []string) error {
	if err := noArgs(args); err != nil {
		return err
	}
	fmt.Printf("module:      %s\n", w.root)
	fmt.Printf("cache:       %s\n", w.cache)
	fmt.Printf("Go release:  %s\n", w.version)
	if out, err := output("", hostGoEnv(), "go", "version"); err == nil {
		fmt.Printf("host Go:     %s\n", strings.TrimSpace(out))
	} else {
		fmt.Printf("host Go:     (none)\n")
	}
	if out, err := output("", nil, "openssl", "version"); err == nil {
		fmt.Printf("OpenSSL:     %s\n", strings.TrimSpace(out))
	} else {
		fmt.Printf("OpenSSL:     (none)\n")
	}
	if out, err := output("", nil, "git", "--version"); err == nil {
		fmt.Printf("git:         %s\n", strings.TrimSpace(out))
	}
	g := w.goroot()
	if err := w.needGoroot(); err != nil {
		fmt.Printf("toolchain:   missing (run: ivory-overlay toolchain -go %s)\n", w.version)
		return err
	}
	v, err := output("", goEnv(g, ""), filepath.Join(g, "bin", "go"), "version")
	if err != nil {
		return err
	}
	fmt.Printf("toolchain:   %s at %s\n", strings.TrimSpace(v), g)
	if _, err := os.Stat(w.pinsFile()); err != nil {
		fmt.Printf("pins:        missing for %s\n", w.version)
		return fmt.Errorf("no pins for %s", w.version)
	}
	fmt.Printf("pins:        %s\n", w.pinsFile())
	ps, err := w.profilePatches()
	if err != nil {
		return err
	}
	if err := checkPins(w.pinsFile(), g, w.version, pristineFiles(ps)); err != nil {
		return err
	}
	fmt.Printf("pin check:   ok (profile %s)\n", w.profile)
	for _, pattern := range []string{"overlay", "goroot"} {
		dirs, _ := filepath.Glob(filepath.Join(w.cache, pattern, w.version+"-*"))
		for _, d := range dirs {
			stamp, err := os.ReadFile(filepath.Join(d, stampFile))
			if err != nil {
				continue
			}
			fmt.Printf("built:       %s\n", d)
			for _, line := range strings.Split(strings.TrimSpace(string(stamp)), "\n") {
				fmt.Printf("             %s\n", line)
			}
		}
	}

	// Build and run a program that uses what the profile's patches add.
	var goroot, goflags, dir string
	if w.materialized {
		goroot, dir = w.materializedDir(), w.materializedDir()
	} else {
		goroot, dir = g, w.overlayDir()
		goflags = "-overlay=" + filepath.Join(dir, "overlay.json")
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return err
	}
	if ok, err := stampIsCurrent(dir, w.version, w.profile, ps); err != nil || !ok {
		fmt.Printf("program:     not run: no current build of profile %s at %s\n", w.profile, dir)
		return fmt.Errorf("no current build of profile %s; run: ivory-overlay build -profile %s", w.profile, w.profile)
	}
	out, err := runDoctorProgram(w, goroot, goflags, ps)
	fmt.Printf("program:     %s\n", strings.ReplaceAll(strings.TrimSpace(out), "\n", "\n             "))
	return err
}

// doctorChecks are the parts of the check program for the patches that add
// API or change parsing, by patch number. The other patches only change
// behavior on the wire; stdtest and the module's tests cover them.
var doctorChecks = []struct {
	prefix, imports, code string
}{
	{"0100", `"crypto/x509" "encoding/pem"`, `
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("P1 FAIL: a certificate with a key on an unsupported curve:", err)
		os.Exit(1)
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || cert.PublicKey != nil {
		fmt.Println("P1 FAIL: want UnknownPublicKeyAlgorithm and a nil PublicKey")
		os.Exit(1)
	}
	fmt.Println("P1 ok: brainpoolP256r1 certificate parsed, key unknown")`},
	{"0200", `"crypto/tls" "crypto/x509"`, `
	_ = tls.Config{VerifyUnsupportedSignature: func(*x509.Certificate, tls.SignatureScheme, []byte, []byte) error { return nil }}
	fmt.Println("P2 ok: Config.VerifyUnsupportedSignature")`},
	{"0300", `"crypto/tls"`, `
	_ = tls.SignatureSchemeOptions{Scheme: 0x081A}
	fmt.Println("P3 ok: SignatureSchemeOptions")`},
	{"0400", `"crypto/tls"`, `
	_ = tls.Config{KeyExchanges: []tls.KeyExchange{{ID: 0x001A, MaxVersion: tls.VersionTLS12}}}
	fmt.Println("P4 ok: Config.KeyExchanges")`},
	{"0500", `"crypto/tls"`, `
	_ = tls.Config{SignatureSchemes: []tls.SignatureScheme{0x081A}}
	fmt.Println("P5 ok: Config.SignatureSchemes")`},
}

// doctorCert is the brainpoolP256r1 test CA certificate of testdata/pki.
const doctorCert = `-----BEGIN CERTIFICATE-----
MIIBtTCCAVqgAwIBAgIUCg83uaoyfbvA1qGyPZn0vcYrYWwwCgYIKoZIzj0EAwIw
JzElMCMGA1UEAwwcaXZvcnkgQnJhaW5wb29sIFAyNTYgVGVzdCBDQTAeFw0yNjEw
MDgwNjQ5MzRaFw0zNjEwMDUwNjQ5MzRaMCcxJTAjBgNVBAMMHGl2b3J5IEJyYWlu
cG9vbCBQMjU2IFRlc3QgQ0EwWjAUBgcqhkjOPQIBBgkrJAMDAggBAQcDQgAEDYtB
PT87bSQb1uNCd2Jz6Zg6tEFkACZiS/byCVQutRhard1ZT2LAY6drLalL56WIBE2N
85GmMzcoFr0VH/7oOaNjMGEwHQYDVR0OBBYEFJk0PSsK2KSJxI+9XjHQ3SFK9/N6
MB8GA1UdIwQYMBaAFJk0PSsK2KSJxI+9XjHQ3SFK9/N6MA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCE+Z6goYoP2k7P
opHKj0wCMsR6cRSup1+wUJnHaLQovgIhAJhtmVfDQyrAAq4GgVHdIyQJ4Y6a6P4y
sPp3dW9Hika+
-----END CERTIFICATE-----
`

// doctorProgram returns the source of the check program for the patches.
func doctorProgram(ps []*patch) string {
	imports := map[string]bool{`"fmt"`: true, `"os"`: true}
	var code strings.Builder
	for _, p := range ps {
		for _, c := range doctorChecks {
			if strings.HasPrefix(p.name, c.prefix+"-") {
				for _, imp := range strings.Fields(c.imports) {
					imports[imp] = true
				}
				code.WriteString(c.code + "\n")
			}
		}
	}
	var src strings.Builder
	src.WriteString("package main\n\nimport (\n")
	for _, imp := range sortedKeys(imports) {
		src.WriteString("\t" + imp + "\n")
	}
	src.WriteString(")\n\nconst certPEM = `" + doctorCert + "`\n\nfunc main() {\n\t_ = os.Exit\n\t_ = certPEM\n")
	src.WriteString(code.String())
	src.WriteString("\tfmt.Println(\"done\")\n}\n")
	return src.String()
}

// runDoctorProgram builds and runs the check program with the toolchain in
// goroot and the given GOFLAGS, in a module of its own.
func runDoctorProgram(w *workspace, goroot, goflags string, ps []*patch) (string, error) {
	dir, err := os.MkdirTemp("", "ivory-doctor-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	series := strings.TrimPrefix(w.version[:strings.LastIndex(w.version, ".")], "go")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module ivorydoctor\n\ngo "+series+"\n"), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(doctorProgram(ps)), 0o644); err != nil {
		return "", err
	}
	cmd := exec.Command(filepath.Join(goroot, "bin", "go"), "run", ".")
	cmd.Dir = dir
	cmd.Env = goEnv(goroot, goflags, "GOWORK=off", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("check program failed: %v", err)
	}
	return string(out), nil
}
