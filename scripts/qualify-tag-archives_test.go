//go:build ignore

// Inert policy/entry-point and genuine file-only Git preparation controls.
// No test substitutes a successful engine or creates fake engine archives.
package main

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestFixedTagReleaseBoundary(t *testing.T) {
	want := []string{"/owned/engine", "release", "--config=.goreleaser.yaml", "--clean", "--skip=publish,announce,sign,notarize,sbom,docker,ko,changelog", "--parallelism=1", "--timeout=10m"}
	if !reflect.DeepEqual(fixedTagRelease("/owned/engine"), want) {
		t.Fatal("fixed nonpublishing argv changed")
	}
	q := tagQualification{root: "/owned", goBin: "/go/bin/go", engine: "/owned/engine", wfctl: "/owned/wfctl"}
	for _, native := range []bool{false, true} {
		env := map[string]string{}
		for _, v := range q.environment(native) {
			k, v, _ := strings.Cut(v, "=")
			if _, ok := env[k]; ok {
				t.Fatal("duplicate execution environment")
			}
			env[k] = v
		}
		for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "RELEASES_TOKEN", "ACTIONS_RUNTIME_TOKEN", "SSH_AUTH_SOCK", "GORELEASER_CURRENT_TAG", "GORELEASER_PREVIOUS_TAG"} {
			if _, ok := env[key]; ok {
				t.Fatal("credential/tag override propagated")
			}
		}
		for k, v := range map[string]string{"GOTOOLCHAIN": "local", "GOAUTH": "off", "GOPROXY": "off", "GOVCS": "*:off", "GIT_ALLOW_PROTOCOL": "file", "GIT_NO_LAZY_FETCH": "1", "GIT_CONFIG_GLOBAL": "/dev/null"} {
			if env[k] != v {
				t.Fatalf("execution boundary %s changed", k)
			}
		}
		if (env["NATIVE_CHECK_RECEIPT"] != "") != native || (env["WFCTL_BIN"] != "") != native {
			t.Fatal("native inputs leaked to other phases")
		}
	}
}

func tagTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z"}
	argv := tagGit(dir, append([]string{"-c", "user.name=QualificationFixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
	b, e := runTagChild(dir, env, argv)
	if e != nil {
		t.Fatalf("owned Git fixture: %v", e)
	}
	return strings.TrimSpace(string(b))
}

func TestOwnedTagCheckout(t *testing.T) {
	for _, name := range []string{"exact", "detached", "wrong-tree"} {
		t.Run(name, func(t *testing.T) {
			wrong := name == "wrong-tree"
			source := t.TempDir()
			if e := os.WriteFile(filepath.Join(source, "source.txt"), []byte("inert owned source\n"), 0600); e != nil {
				t.Fatal(e)
			}
			tagTestGit(t, source, "init", "-q", "-b", "main")
			tagTestGit(t, source, "add", "source.txt")
			tagTestGit(t, source, "commit", "-qm", "inert source")
			branch := tagTestGit(t, source, "rev-parse", "refs/heads/main")
			if name == "detached" {
				tagTestGit(t, source, "checkout", "--detach", "HEAD")
				if e := os.WriteFile(filepath.Join(source, "detached.txt"), []byte("inert detached candidate\n"), 0600); e != nil {
					t.Fatal(e)
				}
				tagTestGit(t, source, "add", "detached.txt")
				tagTestGit(t, source, "commit", "-qm", "inert detached candidate")
			}
			sha, tree := tagTestGit(t, source, "rev-parse", "HEAD"), tagTestGit(t, source, "rev-parse", "HEAD^{tree}")
			root := t.TempDir()
			for _, n := range []string{"execution-home", "execution-tmp"} {
				if e := os.Mkdir(filepath.Join(root, n), 0700); e != nil {
					t.Fatal(e)
				}
			}
			q := tagQualification{sha: sha, tree: tree, root: root, source: source, engine: "/usr/bin/false", goBin: filepath.Join(runtime.GOROOT(), "bin/go"), run: runTagChild}
			if wrong {
				q.tree = strings.Repeat("0", 40)
			}
			dest, e := q.prepareClone()
			if wrong {
				if e == nil {
					t.Fatal("wrong clone tree accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if tagTestGit(t, source, "rev-parse", "refs/heads/main") != branch || tagTestGit(t, source, "rev-parse", "HEAD") != sha {
				t.Fatal("original source refs changed")
			}
			if tagTestGit(t, source, "tag", "--list") != "" {
				t.Fatal("original checkout tags mutated")
			}
			if got := tagTestGit(t, dest, "tag", "--list"); got != qualificationTagReference(t, sha) {
				t.Fatal("owned qualification tag not exact")
			}
			if tagTestGit(t, dest, "rev-parse", "HEAD") != sha || tagTestGit(t, dest, "rev-parse", "HEAD^{tree}") != tree {
				t.Fatal("owned source identity changed")
			}
			if tagTestGit(t, dest, "remote", "get-url", "origin") != "https://github.com/GoCodeAlone/workflow-plugin-compute.git" || tagTestGit(t, dest, "config", "--get", "remote.origin.pushurl") != "disabled://qualification" {
				t.Fatal("canonical metadata/inert push binding changed")
			}
			if _, e := os.Lstat(filepath.Join(dest, ".git/objects/info/alternates")); !os.IsNotExist(e) {
				t.Fatal("shared alternates present")
			}
			b, e := os.ReadFile(filepath.Join(dest, "source.txt"))
			if e != nil || string(b) != "inert owned source\n" {
				t.Fatal("clone raw source differs")
			}
		})
	}
}

func TestTagChildFailureWithholdsOutput(t *testing.T) {
	_, e := runTagChild(t.TempDir(), []string{"PATH=/usr/bin:/bin"}, []string{"/bin/sh", "-c", "printf 'inert-sensitive-output'; printf 'inert-sensitive-error' >&2; exit 7"})
	if e == nil || !strings.Contains(e.Error(), "exit 7") || strings.Contains(e.Error(), "inert-sensitive") {
		t.Fatal("failed child output disclosed")
	}
	var w tagBoundedOutput
	b := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	n, e := w.Write(b)
	if e != nil || n != len(b) || w.Len() != 1<<20 || !w.overflow {
		t.Fatal("bounded accepting output changed")
	}
}

func TestTagToolAuthenticationStopsBeforeExecution(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"execution-home", "execution-tmp", "module-cache", "build-cache", "gopath"} {
		if e := os.Mkdir(filepath.Join(root, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(root, "credentials-removed"), []byte("removed\n"), 0600); e != nil {
		t.Fatal(e)
	}
	tool := filepath.Join(root, "inert-tool")
	if e := os.WriteFile(tool, []byte("inert tool, never executed"), 0700); e != nil {
		t.Fatal(e)
	}
	q := tagQualification{sha: strings.Repeat("1", 40), tree: strings.Repeat("2", 40), root: root, source: root, engine: tool, wfctl: tool, goBin: filepath.Join(runtime.GOROOT(), "bin/go"), run: func(string, []string, []string) ([]byte, error) {
		t.Fatal("unauthenticated tool executed")
		return nil, nil
	}}
	if e := q.execute(&bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "engine authentication failed") {
		t.Fatalf("authentication boundary did not reach expected engine refusal: %v", e)
	}
}

func TestOwnedCredentialResidueBoundary(t *testing.T) {
	b, e := os.ReadFile("../.github/workflows/tag-qualification.yml")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	a := strings.Index(s, "          set +e\n")
	if a < 0 {
		t.Fatal("residue boundary missing")
	}
	z := strings.Index(s[a:], "          test \"$(du -sk")
	if z < 0 {
		t.Fatal("residue boundary missing")
	}
	block := s[a : a+z]
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "residue"}[present], func(t *testing.T) {
			root := t.TempDir()
			value := "harmless input"
			if present {
				value = "inert-residue-marker"
			}
			if e := os.WriteFile(filepath.Join(root, "input"), []byte(value), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", block)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "OWNED_ROOT=" + root, "RELEASES_TOKEN=inert-residue-marker"}
			var out, errout bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errout
			e := cmd.Run()
			if (e != nil) != present || strings.Contains(out.String()+errout.String(), "inert-residue-marker") {
				t.Fatalf("owned residue guard failed: %v", e)
			}
			_, e = os.Lstat(filepath.Join(root, "credentials-removed"))
			if present && !os.IsNotExist(e) {
				t.Fatal("residue created execution marker")
			}
			if !present && e != nil {
				t.Fatal("clean input did not permit execution")
			}
		})
	}
}

func TestTagQualificationCLIRefusals(t *testing.T) {
	script, e := filepath.Abs("qualify-tag-archives.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, cred := range []bool{false, true} {
		t.Run(map[bool]string{false: "unadmitted-runtime", true: "credential"}[cred], func(t *testing.T) {
			args := []string{"run", script, strings.Repeat("1", 40), strings.Repeat("2", 40), "inert", "inert", "inert", "inert", "inert"}
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), args...)
			cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off")
			if cred {
				cmd.Env = append(cmd.Env, "GITHUB_TOKEN=inert-fixture")
			}
			var out, errout bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errout
			e := cmd.Run()
			exit, ok := e.(*exec.ExitError)
			want := "qualification paths must be canonical/absolute"
			if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
				want = "requires local Go1.27.4 linux/amd64"
			}
			if cred {
				want = "credential/tag override environment refused"
			}
			if !ok || exit.ExitCode() != 1 || out.Len() != 0 || !strings.Contains(errout.String(), want) || strings.Contains(errout.String(), "inert-fixture") {
				t.Fatalf("actual orchestration entry-point refusal changed: %v %q", e, errout.String())
			}
		})
	}
}

// Exercise the real subprocess failure entry boundary with finite harmless
// exit7 and owned wire fixtures; never execute a release engine.
func TestTagChildFixedNativeDiagnostics(t *testing.T) {
	good := `{"schema":1,"scope":"native-hook-diagnostic","primary_phase":"verifier","verifier_result":"exited","joined":true,"exit":7,"cleanup":"removed","tmpdir_bytes":99}`
	for _, name := range []string{"valid", "missing", "unknown", "malformed", "oversize", "bad-phase", "bad-number", "bad-schema", "bad-cleanup", "bad-result", "bad-joined", "bad-length", "duplicate", "symlink"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			receipt := filepath.Join(dir, "native.json")
			path := receipt + ".status"
			wire, want := good, `"observation":"refused"`
			switch name {
			case "missing":
				want = `"observation":"not-observed"`
			case "unknown":
				wire = strings.TrimSuffix(good, "}") + `,"inert-private-marker":"inert-private-value"}`
				want = `"observation":"unusable"`
			case "malformed":
				wire = "inert-private-malformed"
				want = `"observation":"unusable"`
			case "oversize":
				wire = strings.Repeat("x", 513)
				want = `"observation":"unusable"`
			case "bad-phase":
				wire = strings.Replace(good, `"primary_phase":"verifier"`, `"primary_phase":"inert-private-phase"`, 1)
				want = `"observation":"unusable"`
			case "bad-number":
				wire = strings.Replace(good, `"exit":7`, `"exit":7.5`, 1)
				want = `"observation":"unusable"`
			case "bad-schema":
				wire = strings.Replace(good, `"schema":1`, `"schema":2`, 1)
				want = `"observation":"unusable"`
			case "bad-cleanup":
				wire = strings.Replace(good, `"cleanup":"removed"`, `"cleanup":"inert-private-cleanup"`, 1)
				want = `"observation":"unusable"`
			case "bad-result":
				wire = strings.Replace(good, `"verifier_result":"exited"`, `"verifier_result":"inert-private-result"`, 1)
				want = `"observation":"unusable"`
			case "bad-joined":
				wire = strings.Replace(good, `"joined":true`, `"joined":false`, 1)
				want = `"observation":"unusable"`
			case "bad-length":
				wire = strings.Replace(good, `"tmpdir_bytes":99`, `"tmpdir_bytes":4097`, 1)
				want = `"observation":"unusable"`
			case "duplicate":
				wire = strings.TrimSuffix(good, "}") + `,"exit":7}`
				want = `"observation":"unusable"`
			case "symlink":
				want = `"observation":"unusable"`
			}
			if name != "missing" {
				dest := path
				if name == "symlink" {
					dest = filepath.Join(dir, "inert-target")
				}
				if e := os.WriteFile(dest, []byte(wire), 0600); e != nil {
					t.Fatal(e)
				}
				if name == "symlink" {
					if e := os.Symlink(dest, path); e != nil {
						t.Fatal(e)
					}
				}
			}
			_, e := runTagChild(t.TempDir(), []string{"PATH=/usr/bin:/bin", "NATIVE_CHECK_RECEIPT=" + receipt}, []string{"/bin/sh", "-c", "printf inert-private-output; printf inert-private-error >&2; exit 7"})
			if e == nil || !strings.Contains(e.Error(), "exit 7") || !strings.Contains(e.Error(), want) || strings.Contains(e.Error(), "private") || strings.Contains(e.Error(), dir) {
				t.Fatalf("fixed diagnostic boundary missing: %v", e)
			}
		})
	}
}

// Actual native producer function -> its exact wire bytes -> actual driver
// subprocess-error consumer. Only the verifier is a finite inert shell helper;
// this is not a release engine/wfctl/plugin invocation or native acceptance.
func TestTagNativeDiagnosticProducerCrossing(t *testing.T) {
	argv := []string{filepath.Join(runtime.GOROOT(), "bin/go"), "test", "-v", "-count=1", "-p=1", "-timeout=30s", "-run", "^TestNativeFailureDiagnostics/verifier$", "check-native-release.go", "check-native-release_test.go"}
	b, e := runTagChild(".", os.Environ(), argv)
	if e != nil {
		t.Fatal(e)
	}
	recordNestedNativeWorkspaces(t, b)
	var wire string
	for _, line := range strings.Split(string(b), "\n") {
		if _, v, ok := strings.Cut(line, "NATIVE_DIAGNOSTIC_FIXTURE:"); ok {
			if wire != "" {
				t.Fatal("ambiguous producer fixture")
			}
			wire = v
		}
	}
	if wire == "" {
		t.Fatal("actual native diagnostic producer not observed")
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	receipt := filepath.Join(dir, "native.json")
	if e := os.WriteFile(receipt+".status", []byte(wire), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = runTagChild(t.TempDir(), []string{"PATH=/usr/bin:/bin", "NATIVE_CHECK_RECEIPT=" + receipt}, []string{"/bin/sh", "-c", "exit 7"})
	if e == nil || !strings.Contains(e.Error(), `"observation":"refused"`) || !strings.Contains(e.Error(), `"primary_phase":"verifier"`) || !strings.Contains(e.Error(), `"joined":true`) {
		t.Fatalf("actual wire did not cross strict consumer: %v", e)
	}
}

func TestTagDiagnosticFreshnessBeforeExecution(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"execution-home", "execution-tmp", "module-cache", "build-cache", "gopath"} {
		if e := os.Mkdir(filepath.Join(root, n), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(root, "native.json.status"), []byte("inert preexisting status"), 0600); e != nil {
		t.Fatal(e)
	}
	q := tagQualification{sha: strings.Repeat("1", 40), tree: strings.Repeat("2", 40), root: root, source: root, engine: "/inert/engine", wfctl: "/inert/wfctl", goBin: filepath.Join(runtime.GOROOT(), "bin/go"), run: func(string, []string, []string) ([]byte, error) {
		t.Fatal("stale diagnostic reached execution")
		return nil, nil
	}}
	if e := q.execute(&bytes.Buffer{}); e == nil || !strings.Contains(e.Error(), "receipts must be fresh") {
		t.Fatalf("stale diagnostic not refused before execution: %v", e)
	}
}

func TestTagReportedReasonWire(t *testing.T) {
	good := `{"schema":1,"scope":"native-hook-diagnostic","primary_phase":"verifier","verifier_result":"exited","joined":true,"exit":1,"cleanup":"removed","tmpdir_bytes":99,"reason_hint":"reported-unix-socket-path-length","socket_path_bytes":108}`
	for _, name := range []string{"valid", "unknown-hint", "fits-budget", "wrong-length", "wrong-hint-shape", "not-joined", "exit-zero", "wrong-phase", "hint-absent"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			receipt := filepath.Join(dir, "native.json")
			wire := good
			want := `"observation":"unusable"`
			switch name {
			case "valid":
				want = `"observation":"refused"`
			case "unknown-hint":
				wire = strings.Replace(good, "reported-unix-socket-path-length", "inert-private-cause", 1)
			case "fits-budget":
				wire = strings.Replace(good, `"socket_path_bytes":108`, `"socket_path_bytes":107`, 1)
			case "wrong-length":
				wire = strings.Replace(good, `"socket_path_bytes":108`, `"socket_path_bytes":117`, 1)
			case "wrong-hint-shape":
				wire = strings.Replace(good, "reported-unix-socket-path-length", "reported-plugin-handshake", 1)
			case "not-joined":
				wire = strings.Replace(good, `"joined":true`, `"joined":false`, 1)
			case "exit-zero":
				wire = strings.Replace(good, `"exit":1`, `"exit":0`, 1)
			case "wrong-phase":
				wire = strings.Replace(good, `"primary_phase":"verifier"`, `"primary_phase":"postcheck"`, 1)
			case "hint-absent":
				wire = strings.Replace(good, `,"reason_hint":"reported-unix-socket-path-length"`, "", 1)
			}
			if e := os.WriteFile(receipt+".status", []byte(wire), 0600); e != nil {
				t.Fatal(e)
			}
			_, e := runTagChild(t.TempDir(), []string{"PATH=/usr/bin:/bin", "NATIVE_CHECK_RECEIPT=" + receipt}, []string{"/bin/sh", "-c", "exit 1"})
			if e == nil || !strings.Contains(e.Error(), want) || strings.Contains(e.Error(), "private") {
				t.Fatal("strict consumer accepted or disclosed malformed reported hint")
			}
		})
	}
}

func TestTagReportedReasonProducerCrossing(t *testing.T) {
	argv := []string{filepath.Join(runtime.GOROOT(), "bin/go"), "test", "-v", "-count=1", "-p=1", "-timeout=30s", "-run", "^TestNativeReportedReasonActualFunction$", "check-native-release.go", "check-native-release_test.go"}
	b, e := runTagChild(".", os.Environ(), argv)
	if e != nil {
		t.Fatal("finite actual producer fixture failed")
	}
	recordNestedNativeWorkspaces(t, b)
	var wire string
	for _, line := range strings.Split(string(b), "\n") {
		if _, v, ok := strings.Cut(line, "NATIVE_REPORTED_REASON_FIXTURE:"); ok {
			if wire != "" {
				t.Fatal("ambiguous producer fixture")
			}
			wire = v
		}
	}
	if wire == "" {
		t.Fatal("actual reported-text producer was not observed")
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	receipt := filepath.Join(dir, "native.json")
	if e := os.WriteFile(receipt+".status", []byte(wire), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = runTagChild(t.TempDir(), []string{"PATH=/usr/bin:/bin", "NATIVE_CHECK_RECEIPT=" + receipt}, []string{"/bin/sh", "-c", "exit 1"})
	if e == nil || !strings.Contains(e.Error(), `"observation":"refused"`) || !strings.Contains(e.Error(), `"reason_hint":"reported-plugin-handshake"`) {
		t.Fatal("actual reported-text wire did not cross strict consumer")
	}
}

func recordNestedNativeWorkspaces(t *testing.T, b []byte) {
	t.Helper()
	parent, e := filepath.EvalSymlinks("/tmp")
	if e != nil {
		t.Fatal("cannot resolve native workspace ledger parent")
	}
	for _, line := range strings.Split(string(b), "\n") {
		_, path, ok := strings.Cut(line, "OWNED_NATIVE_TMP:")
		if !ok {
			continue
		}
		path = strings.TrimSpace(path)
		if filepath.Dir(path) != parent || !regexp.MustCompile(`^nc-[A-Za-z0-9_-]{22}$`).MatchString(filepath.Base(path)) {
			t.Fatal("nested native ledger escaped fixed temp scope")
		}
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("nested producer left its owned native directory")
		}
		t.Logf("OWNED_NATIVE_TMP:%s", path)
	}
}

func qualificationTagReference(t *testing.T, sha string) string {
	t.Helper()
	n, ok := new(big.Int).SetString(sha, 16)
	if !ok {
		t.Fatal("reference SHA parse")
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 52), big.NewInt(1))
	patch := new(big.Int).And(new(big.Int).Set(n), mask)
	minor := new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(n), 52), mask)
	major := new(big.Int).Rsh(new(big.Int).Set(n), 104)
	return "v" + major.String() + "." + minor.String() + "." + patch.String()
}
func TestNumericQualificationTag(t *testing.T) {
	vectors := []struct{ sha, tag string }{
		{"0000000000000000000000000008000000000000", "v0.0.2251799813685248"},
		{"0000000000000000000000000020000000000000", "v0.2.0"},
		{"0000000000000080000000000000000000000000", "v0.2251799813685248.0"},
		{"0000000000000200000000000000000000000000", "v2.0.0"},

		{"0000000000000000000000000000000000000001", "v0.0.1"},
		{"0000000000000000000000000010000000000000", "v0.1.0"},
		{"0000000000000100000000000000000000000000", "v1.0.0"},
		{"8000000000000000000000000000000000000000", "v36028797018963968.0.0"},
		{"ffffffffffffffffffffffffffffffffffffffff", "v72057594037927935.4503599627370495.4503599627370495"},
		{"672c413c33732d1cad1c57166089e93ecd5dc3c7", "v29040581295698733.504477286229512.2789730733114311"},
	}
	for _, tc := range vectors {
		tag, e := numericQualificationTag(tc.sha)
		if e != nil || tag != tc.tag || tag != qualificationTagReference(t, tc.sha) {
			t.Fatal("qualification tag differs from independent full-SHA numeric contract")
		}
		parts := strings.Split(strings.TrimPrefix(tag, "v"), ".")
		if len(parts) != 3 {
			t.Fatal("numeric qualification tag is not legacy-compatible")
		}
		n := new(big.Int)
		for index, p := range parts {
			value, e := strconv.ParseUint(p, 10, 63)
			if e != nil || strconv.FormatUint(value, 10) != p {
				t.Fatal("component exceeds signed64 or is noncanonical")
			}
			if _, e := strconv.Atoi(p); e != nil {
				t.Fatal("released legacy parser's integer operation rejects component")
			}
			if index > 0 {
				n.Lsh(n, 52)
			}
			n.Add(n, new(big.Int).SetUint64(value))
		}
		if fmt.Sprintf("%040x", n) != tc.sha {
			t.Fatal("numeric tag lost or reordered SHA bits")
		}
	}
	for _, bad := range []string{"", strings.Repeat("0", 40), strings.Repeat("A", 40), strings.Repeat("f", 39), strings.Repeat("f", 41), strings.Repeat("g", 40)} {
		if _, e := numericQualificationTag(bad); e == nil {
			t.Fatal("invalid or sentinel source accepted")
		}
	}
}
