//go:build ignore

// Named-file, stdlib-only controls. Digest/host seams are unit-only; main has
// fixed production policy. No test launches wfctl or an actual plugin binary.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func nativeFixture(t *testing.T) (string, []string, nativeCheckOptions) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "dist"), 0700); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string]string{"plugin.json": `{"name":"inert-fixture","version":"1.2.3"}`, "dist/plugin": "inert artifact bytes, never executed", "verifier": "inert verifier bytes, not an executable program"} {
		if e = os.WriteFile(filepath.Join(root, name), []byte(body), 0700); e != nil {
			t.Fatal(e)
		}
	}
	tool := filepath.Join(root, "verifier")
	digest, e := nativeDigest(tool, 160<<20, true)
	if e != nil {
		t.Fatal(e)
	}
	opt := nativeCheckOptions{host: "linux/amd64", tool: tool, digest: digest, afterCleanup: os.RemoveAll, run: func(*exec.Cmd) error { t.Fatal("unexpected process invocation"); return nil }}
	opt.workspace = func() (*nativeWorkspace, error) {
		w, e := newNativeWorkspace()
		if e == nil {
			t.Logf("OWNED_NATIVE_TMP:%s", w.path)
			t.Cleanup(func() {
				if _, e := os.Lstat(w.path); !os.IsNotExist(e) {
					t.Error("owned native workspace leaked after command return")
				}
			})
		}
		return w, e
	}
	// v2.20.3 base.OptionsForTarget uses filepath.Abs for the actual hook .Path.
	return root, []string{"linux", "amd64", filepath.Join(root, "dist/plugin"), "false"}, opt
}

func nativeEnvironment(t *testing.T, cmd *exec.Cmd, root string) string {
	t.Helper()
	if cmd.Dir != root || cmd.Stdin != nil || cmd.Stdout != io.Discard || cmd.Stderr == nil || cmd.Stderr == io.Discard {
		t.Fatal("cwd or standard streams changed")
	}
	capture, ok := cmd.Stderr.(interface{ Len() int })
	if !ok || capture.Len() != 0 {
		t.Fatal("stderr is not a fresh bounded private capture")
	}
	values := map[string]string{}
	for _, entry := range cmd.Env {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || values[k] != "" {
			t.Fatal("ambiguous child environment")
		}
		values[k] = v
	}
	if len(values) != 9 || values["PATH"] != "/usr/bin:/bin" || values["LANG"] != "C" || values["LC_ALL"] != "C" || values["WFCTL_DIFFCACHE"] != ":memory:" || values["GIT_CONFIG_NOSYSTEM"] != "1" || values["GIT_CONFIG_GLOBAL"] != "/dev/null" || values["GIT_TERMINAL_PROMPT"] != "0" {
		t.Fatal("child environment is not the exact allowlist")
	}
	for _, name := range []string{"HOME", "TMPDIR"} {
		st, e := os.Stat(values[name])
		if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
			t.Fatal("child private environment is not owned/private")
		}
	}
	owned := filepath.Dir(values["HOME"])
	if values["TMPDIR"] != owned || owned == root {
		t.Fatal("child environment ownership changed")
	}
	return owned
}

func TestNativeReleaseInvocationPolicy(t *testing.T) {
	root, args, opt := nativeFixture(t)
	calls, owned := 0, ""
	opt.run = func(cmd *exec.Cmd) error {
		calls++
		if cmd.Path != opt.tool || !reflect.DeepEqual(cmd.Args, []string{opt.tool, "plugin", "verify-capabilities", "--binary", filepath.Join(root, "dist/plugin"), root}) {
			t.Fatal("exact verifier/artifact argv changed")
		}
		owned = nativeEnvironment(t, cmd, root)
		_, _ = cmd.Stdout.Write([]byte("inert output marker"))
		_, _ = cmd.Stderr.Write([]byte("inert diagnostic marker"))
		return nil
	}
	result, e := checkNativeRelease(root, args, opt)
	if e != nil || calls != 1 || !strings.Contains(result, "full capability parity not asserted") {
		t.Fatalf("native policy crossing failed: %v", e)
	}
	if _, e = os.Lstat(owned); !os.IsNotExist(e) {
		t.Fatal("owned child environment remains")
	}
	if nativeWfctlSHA != "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8" {
		t.Fatal("reviewed production authentication pin changed")
	}
}

func TestNativeReleaseRelativeArtifact(t *testing.T) {
	root, args, opt := nativeFixture(t)
	args[2] = "dist/plugin"
	calls := 0
	opt.run = func(cmd *exec.Cmd) error {
		calls++
		if cmd.Args[4] != filepath.Join(root, "dist/plugin") {
			t.Fatal("relative artifact was not resolved to the exact source root")
		}
		return nil
	}
	if _, e := checkNativeRelease(root, args, opt); e != nil || calls != 1 {
		t.Fatalf("relative artifact policy failed: %v", e)
	}
}

func TestNativeReleaseReceipt(t *testing.T) {
	for _, name := range []string{"success", "child-failure", "cleanup-failure", "existing", "source-path", "snapshot", "cross"} {
		t.Run(name, func(t *testing.T) {
			root, args, opt := nativeFixture(t)
			receiptRoot := t.TempDir()
			if e := os.Chmod(receiptRoot, 0700); e != nil {
				t.Fatal(e)
			}
			opt.receipt = filepath.Join(receiptRoot, "native.json")
			called, cleaned := 0, false
			opt.run = func(cmd *exec.Cmd) error {
				called++
				nativeEnvironment(t, cmd, root)
				for _, e := range cmd.Env {
					if strings.HasPrefix(e, "NATIVE_CHECK_RECEIPT=") {
						t.Fatal("receipt destination leaked to plugin environment")
					}
				}
				if _, e := os.Lstat(opt.receipt); !os.IsNotExist(e) {
					t.Fatal("receipt exists before native check completes")
				}
				if name == "child-failure" {
					return errors.New("inert verifier failure")
				}
				return nil
			}
			opt.afterCleanup = func(path string) error {
				cleaned = true
				if e := os.RemoveAll(path); e != nil {
					return e
				}
				if name == "cleanup-failure" {
					return errors.New("inert cleanup failure")
				}
				return nil
			}
			switch name {
			case "existing":
				if e := os.WriteFile(opt.receipt, []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			case "source-path":
				opt.receipt = filepath.Join(root, "receipt.json")
			case "snapshot":
				args[3] = "true"
			case "cross":
				args[0], args[1] = "darwin", "arm64"
			}
			_, e := checkNativeRelease(root, args, opt)
			if name == "success" {
				if e != nil || called != 1 || !cleaned {
					t.Fatalf("receipt producer failed: %v", e)
				}
				b, e := os.ReadFile(opt.receipt)
				if e != nil {
					t.Fatal(e)
				}
				var record nativeValidationReceipt
				if e = json.Unmarshal(b, &record); e != nil {
					t.Fatal(e)
				}
				a, _ := nativeDigest(filepath.Join(root, "dist/plugin"), 128<<20, true)
				m, _ := nativeDigest(filepath.Join(root, "plugin.json"), 64<<10, false)
				if record.Schema != 1 || record.Scope != "runtime-identity-version-declared-iac" || record.Verdict != "pass" || record.Target != "linux-amd64" || record.Artifact != "dist/plugin" || record.ArtifactSHA != a || record.ManifestSHA != m || record.VerifierSHA != opt.digest {
					t.Fatal("receipt not bound to actual invocation inputs")
				}
				st, _ := os.Stat(opt.receipt)
				if st.Mode().Perm() != 0600 {
					t.Fatal("receipt mode not private")
				}
				return
			}
			if name == "snapshot" || name == "cross" {
				if e != nil || called != 0 {
					t.Fatal("skip created runtime evidence")
				}
			} else if e == nil {
				t.Fatal("invalid receipt path/failure accepted")
			}
			if name == "child-failure" || name == "cleanup-failure" {
				if called != 1 || !cleaned {
					t.Fatal("failure control did not reach the actual invocation/cleanup boundary")
				}
			}
			if name == "existing" {
				b, _ := os.ReadFile(opt.receipt)
				if string(b) != "preserve" || called != 0 {
					t.Fatal("existing receipt overwritten or verifier started")
				}
			} else if _, e := os.Lstat(opt.receipt); !os.IsNotExist(e) {
				t.Fatal("failure or skip emitted success receipt")
			}
		})
	}
}

func TestNativeReleaseRefusals(t *testing.T) {
	for _, name := range []string{"wrong-host", "unsupported-target", "invalid-snapshot", "extra-argument", "missing-tool", "relative-tool", "tool-symlink", "wrong-tool-digest", "tool-not-executable", "outside-artifact", "absolute-outside-artifact", "noncanonical-absolute-artifact", "manifest-as-artifact", "artifact-symlink", "artifact-parent-symlink", "artifact-not-executable", "manifest-symlink", "empty-manifest", "large-manifest"} {
		t.Run(name, func(t *testing.T) {
			root, args, opt := nativeFixture(t)
			link := func(path, target string) {
				t.Helper()
				if e := os.Rename(path, target); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, path); e != nil {
					t.Fatal(e)
				}
			}
			switch name {
			case "wrong-host":
				opt.host = "darwin/arm64"
			case "unsupported-target":
				args[1] = "arm64"
			case "invalid-snapshot":
				args[3] = "TRUE"
			case "extra-argument":
				args = append(args, "inert-extra")
			case "missing-tool":
				opt.tool = filepath.Join(root, "missing")
			case "relative-tool":
				opt.tool = "verifier"
			case "tool-symlink":
				link(opt.tool, opt.tool+"-target")
			case "wrong-tool-digest":
				opt.digest = strings.Repeat("0", 64)
			case "tool-not-executable":
				if e := os.Chmod(opt.tool, 0600); e != nil {
					t.Fatal(e)
				}
			case "outside-artifact":
				args[2] = "../inert-outside"
			case "absolute-outside-artifact":
				args[2] = root + "-outside/dist/plugin"
			case "noncanonical-absolute-artifact":
				args[2] = root + "/dist/../dist/plugin"
			case "manifest-as-artifact":
				args[2] = filepath.Join(root, "plugin.json")
			case "artifact-symlink":
				p := filepath.Join(root, "dist/plugin")
				link(p, p+"-target")
			case "artifact-parent-symlink":
				p := filepath.Join(root, "dist")
				link(p, p+"-target")
			case "artifact-not-executable":
				if e := os.Chmod(filepath.Join(root, "dist/plugin"), 0600); e != nil {
					t.Fatal(e)
				}
			case "manifest-symlink":
				p := filepath.Join(root, "plugin.json")
				link(p, p+"-target")
			case "empty-manifest":
				if e := os.WriteFile(filepath.Join(root, "plugin.json"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "large-manifest":
				if e := os.WriteFile(filepath.Join(root, "plugin.json"), bytes.Repeat([]byte{'x'}, (64<<10)+1), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if result, e := checkNativeRelease(root, args, opt); e == nil || result != "" {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

func TestNativeReleaseMutationAndFailure(t *testing.T) {
	for _, name := range []string{"artifact", "manifest", "tool", "cleanup-after-success", "primary-and-cleanup"} {
		t.Run(name, func(t *testing.T) {
			root, args, opt := nativeFixture(t)
			primary, cleanup := errors.New("inert primary"), errors.New("inert cleanup")
			owned := ""
			opt.run = func(cmd *exec.Cmd) error {
				owned = nativeEnvironment(t, cmd, root)
				if name == "primary-and-cleanup" {
					return primary
				}
				if name == "cleanup-after-success" {
					return nil
				}
				p := map[string]string{"artifact": "dist/plugin", "manifest": "plugin.json", "tool": "verifier"}[name]
				return os.WriteFile(filepath.Join(root, p), []byte("inert changed bytes"), 0700)
			}
			if name == "primary-and-cleanup" || name == "cleanup-after-success" {
				opt.afterCleanup = func(p string) error {
					if e := os.RemoveAll(p); e != nil {
						return e
					}
					return cleanup
				}
			}
			result, e := checkNativeRelease(root, args, opt)
			if e == nil || result != "" {
				t.Fatal("changed input/failure accepted")
			}
			if name == "primary-and-cleanup" && (!errors.Is(e, primary) || !errors.Is(e, cleanup)) {
				t.Fatal("primary or cleanup identity lost")
			}
			if name == "cleanup-after-success" && !errors.Is(e, cleanup) {
				t.Fatal("cleanup failure did not fail closed")
			}
			if _, e = os.Lstat(owned); !os.IsNotExist(e) {
				t.Fatal("owned child directory remains")
			}
		})
	}
}

func TestNativeReleaseInertExecutable(t *testing.T) {
	for _, code := range []string{"0", "7"} {
		t.Run("exit-"+code, func(t *testing.T) {
			root, args, opt := nativeFixture(t)
			body := "#!/bin/sh\n[ \"$#\" = 5 ] || exit 11\n[ \"$1\" = plugin ] && [ \"$2\" = verify-capabilities ] && [ \"$3\" = --binary ] || exit 12\nprintf 'inert output discarded'\nprintf 'inert diagnostic discarded' >&2\nexit " + code + "\n"
			if e := os.WriteFile(opt.tool, []byte(body), 0700); e != nil {
				t.Fatal(e)
			}
			var e error
			opt.digest, e = nativeDigest(opt.tool, 160<<20, true)
			if e != nil {
				t.Fatal(e)
			}
			owned := ""
			opt.run = func(cmd *exec.Cmd) error { owned = nativeEnvironment(t, cmd, root); return cmd.Run() }
			_, e = checkNativeRelease(root, args, opt)
			if (code == "0") != (e == nil) {
				t.Fatalf("finite inert invocation outcome: %v", e)
			}
			if code == "7" {
				var exit *exec.ExitError
				if !errors.As(e, &exit) || exit.ExitCode() != 7 {
					t.Fatal("child exit identity lost")
				}
			}
			if _, e = os.Lstat(owned); !os.IsNotExist(e) {
				t.Fatal("finite child environment remains")
			}
		})
	}
}

func TestNativeReleaseCLI(t *testing.T) {
	root, args, opt := nativeFixture(t)
	script, e := filepath.Abs("check-native-release.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
		fail bool
	}{
		{"snapshot", []string{"linux", "amd64", "unused", "true"}, "runtime check not performed", false},
		{"cross", []string{"darwin", "arm64", "unused", "false"}, "runtime check not performed", false},
		{"unsupported", []string{"linux", "arm64", "unused", "true"}, "unsupported release target", true},
		{"malformed", []string{"linux", "amd64", "unused", "TRUE"}, "expected OS ARCH ARTIFACT SNAPSHOT_BOOL", true},
		{"native-refusal", args, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), append([]string{"run", script}, tc.args...)...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "WFCTL_BIN="+opt.tool)
			var out, errout bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errout
			e := cmd.Run()
			want := tc.want
			if tc.name == "native-refusal" {
				want = "native release verification requires a linux/amd64 host"
				if runtime.GOOS+"/"+runtime.GOARCH == "linux/amd64" {
					want = "wfctl authentication failed"
				}
			}
			if tc.fail {
				var exit *exec.ExitError
				if !errors.As(e, &exit) || exit.ExitCode() != 1 || out.Len() != 0 || !strings.Contains(errout.String(), want) {
					t.Fatalf("actual CLI refusal changed: %v %q", e, errout.String())
				}
			} else if e != nil || errout.Len() != 0 || !strings.Contains(out.String(), want) {
				t.Fatalf("actual CLI skip scope changed: %v %q", e, errout.String())
			}
		})
	}
}

// Real native checker function and, for the verifier cases, a finite harmless
// shell helper. No wfctl/plugin, sockets or encryption is invoked.
func TestNativeFailureDiagnostics(t *testing.T) {
	for _, name := range []string{"tool", "verifier", "verifier-and-cleanup", "cleanup", "postcheck", "receipt", "existing-status"} {
		t.Run(name, func(t *testing.T) {
			root, args, opt := nativeFixture(t)
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			opt.receipt = filepath.Join(dir, "native.json")
			path := opt.receipt + ".status"
			calls := 0
			opt.run = func(*exec.Cmd) error { calls++; return nil }
			cleanupFailure := errors.New("inert-cleanup-private-marker")
			primary := "tool"
			cleanup := "not-created"
			joined := false
			switch name {
			case "tool":
				opt.digest = strings.Repeat("0", 64)
			case "verifier", "verifier-and-cleanup":
				if e := os.WriteFile(opt.tool, []byte("#!/bin/sh\nprintf inert-private-output\nprintf inert-private-error >&2\nexit 7\n"), 0700); e != nil {
					t.Fatal(e)
				}
				opt.digest, _ = nativeDigest(opt.tool, 160<<20, true)
				opt.run = func(c *exec.Cmd) error { calls++; return c.Run() }
				primary, cleanup, joined = "verifier", "removed", true
			case "cleanup":
				primary, cleanup = "none", "failed"
			case "postcheck":
				primary, cleanup = "postcheck", "removed"
				opt.run = func(*exec.Cmd) error {
					calls++
					return os.WriteFile(filepath.Join(root, "dist/plugin"), []byte("inert changed artifact"), 0700)
				}
			case "receipt":
				primary, cleanup = "receipt", "removed"
				opt.run = func(*exec.Cmd) error { calls++; return os.WriteFile(opt.receipt, []byte("preserve inert file"), 0600) }
			case "existing-status":
				if e := os.WriteFile(path, []byte("preserve inert status"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if name == "cleanup" || name == "verifier-and-cleanup" {
				if name == "verifier-and-cleanup" {
					cleanup = "failed"
				}
				opt.afterCleanup = func(p string) error {
					if e := os.RemoveAll(p); e != nil {
						return e
					}
					return cleanupFailure
				}
			}
			suppliedTmpBytes := 0
			run := opt.run
			opt.run = func(c *exec.Cmd) error {
				for _, v := range c.Env {
					if strings.HasPrefix(v, "TMPDIR=") {
						suppliedTmpBytes = len(strings.TrimPrefix(v, "TMPDIR="))
					}
				}
				return run(c)
			}
			result, e := checkNativeRelease(root, args, opt)
			if name == "existing-status" {
				b, _ := os.ReadFile(path)
				if e == nil || calls != 0 || string(b) != "preserve inert status" {
					t.Fatal("preexisting diagnostic did not stop before invocation")
				}
				return
			}
			if e == nil || result != "" {
				t.Fatal("failed gate did not fail")
			}
			if name == "cleanup" || name == "verifier-and-cleanup" {
				if !errors.Is(e, cleanupFailure) {
					t.Fatal("cleanup error identity lost")
				}
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("fixed failure diagnostic missing: %v", readErr)
			}
			if len(b) > 512 || bytes.Contains(b, []byte("private")) || bytes.Contains(b, []byte(root)) || bytes.Contains(b, []byte(opt.tool)) {
				t.Fatal("diagnostic disclosed raw input/output or exceeded bound")
			}
			var d map[string]any
			if e := json.Unmarshal(b, &d); e != nil {
				t.Fatal(e)
			}
			if d["schema"] != float64(1) || d["scope"] != "native-hook-diagnostic" || d["primary_phase"] != primary || d["cleanup"] != cleanup || d["joined"] != joined {
				t.Fatalf("incorrect fixed diagnostic facts: %s", b)
			}
			if joined {
				var exited *exec.ExitError
				if !errors.As(e, &exited) || exited.ExitCode() != 7 {
					t.Fatal("primary exit identity lost")
				}
				if d["exit"] != float64(7) || d["verifier_result"] != "exited" {
					t.Fatal("actual joined exit missing")
				}
			} else if _, ok := d["exit"]; ok {
				t.Fatal("exit fabricated without completed command state")
			}
			if name == "tool" {
				if _, ok := d["tmpdir_bytes"]; ok {
					t.Fatal("TMPDIR length fabricated before construction")
				}
			} else if n, ok := d["tmpdir_bytes"].(float64); !ok || n != float64(suppliedTmpBytes) || n <= 0 || n > 4096 {
				t.Fatal("exact child temporary path length missing")
			}
			st, statErr := os.Stat(path)
			if statErr != nil || st.Mode().Perm() != 0600 {
				t.Fatal("diagnostic file is not private")
			}
			if name == "verifier" {
				t.Logf("NATIVE_DIAGNOSTIC_FIXTURE:%s", b)
			}
			if name != "receipt" {
				if _, e := os.Lstat(opt.receipt); !os.IsNotExist(e) {
					t.Fatal("failed gate emitted success receipt")
				}
			}
		})
	}
}

func TestNativeDiagnosticWriteFailurePreservesPrimary(t *testing.T) {
	root, args, opt := nativeFixture(t)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	opt.receipt = filepath.Join(dir, "native.json")
	if e := os.WriteFile(opt.tool, []byte("#!/bin/sh\nexit 7\n"), 0700); e != nil {
		t.Fatal(e)
	}
	opt.digest, _ = nativeDigest(opt.tool, 160<<20, true)
	var primaryErr error
	opt.run = func(c *exec.Cmd) error {
		if e := os.WriteFile(opt.receipt+".status", []byte("preserve inert record"), 0600); e != nil {
			t.Fatal(e)
		}
		primaryErr = c.Run()
		return primaryErr
	}
	_, e := checkNativeRelease(root, args, opt)
	var exit *exec.ExitError
	if primaryErr == nil || !errors.Is(e, primaryErr) || !errors.As(e, &exit) || exit.ExitCode() != 7 || !strings.Contains(e.Error(), "native diagnostic failed") {
		t.Fatal("diagnostic write failure swallowed primary exit")
	}
	b, _ := os.ReadFile(opt.receipt + ".status")
	if string(b) != "preserve inert record" {
		t.Fatal("diagnostic overwrote a competing record")
	}
	if _, e := os.Lstat(opt.receipt); !os.IsNotExist(e) {
		t.Fatal("failure emitted accepted receipt")
	}
}

func TestNativeReceiptResolvedSourceRefusal(t *testing.T) {
	root, args, opt := nativeFixture(t)
	parent := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "inside"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(root, filepath.Join(parent, "owned-alias")); e != nil {
		t.Fatal(e)
	}
	opt.receipt = filepath.Join(parent, "owned-alias", "inside", "native.json")
	calls := 0
	opt.run = func(*exec.Cmd) error { calls++; return nil }
	_, e := checkNativeRelease(root, args, opt)
	if e == nil || !strings.Contains(e.Error(), "outside source") || calls != 0 {
		t.Fatal("resolved source-local destination accepted")
	}
	entries, e := os.ReadDir(filepath.Join(root, "inside"))
	if e != nil || len(entries) != 0 {
		t.Fatal("refused destination changed source")
	}
}

// Pure source-bound pathname arithmetic and synthetic reported text only.
// No test binds, connects to or probes a socket.
func TestNativeReportedReasonBoundaries(t *testing.T) {
	tmp99 := "/" + strings.Repeat("a", 98)
	tmp90 := "/" + strings.Repeat("b", 89)
	for _, tc := range []struct {
		name, tmp, text, want string
		overflow              bool
		size                  int
	}{
		{"107-fits", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin0: bind: invalid argument", "reported-plugin-handshake", false, 0},
		{"108-overflows", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin10: bind: invalid argument", "reported-unix-socket-path-length", false, 108},
		{"116-upper-bound", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin4294967295: bind: invalid argument", "reported-unix-socket-path-length", false, 116},
		{"short-worst-case-fits", tmp90, "plugin dial: listen unix " + tmp90 + "/plugin4294967295: bind: invalid argument", "reported-plugin-handshake", false, 0},
		{"leading-zero", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin042: bind: invalid argument", "unclassified", false, 0},
		{"uint32-overflow", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin4294967296: bind: invalid argument", "unclassified", false, 0},
		{"wrong-tmp", tmp99, "plugin dial: listen unix /inert-other/plugin42: bind: invalid argument", "unclassified", false, 0},
		{"wrong-errno", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin42: bind: permission denied", "unclassified", false, 0},
		{"ambiguous", tmp99, strings.Repeat("plugin dial: listen unix "+tmp99+"/plugin42: bind: invalid argument\n", 2), "unclassified", false, 0},
		{"conflicting", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin42: bind: invalid argument\nGetManifest RPC: inert-private-value", "unclassified", false, 0},
		{"truncated", tmp99, "plugin dial: listen unix " + tmp99 + "/plugin42: bind: invalid argument", "unclassified", true, 0},
		{"manifest-parse", tmp99, "wfctl: plugin.json parse: inert-private-value", "reported-manifest-parse", false, 0},
		{"manifest-validation", tmp99, "wfctl: plugin.json validate: inert-private-value", "reported-manifest-validation", false, 0},
		{"manifest-rpc", tmp99, "wfctl: GetManifest RPC: inert-private-value", "reported-manifest-rpc", false, 0},
		{"contract-rpc", tmp99, "wfctl: GetContractRegistry RPC: inert-private-value", "reported-contract-rpc", false, 0},
		{"manifest-mismatch", tmp99, "wfctl: verify-capabilities: 2 mismatch(es): inert-private-value", "reported-manifest-mismatch", false, 0},
		{"misleading-socket-substring", tmp99, "inertnotlisten unix " + tmp99 + "/plugin42: bind: invalid argument", "unclassified", false, 0},
		{"misleading-substring", tmp99, "inertnotplugin dial: inert-private-value", "unclassified", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, n := classifyNativeReportedError(tc.text, tc.tmp, tc.overflow)
			if got != tc.want || (n == nil) != (tc.size == 0) || (n != nil && *n != tc.size) {
				t.Fatal("reported-text category or bounded length differs from source contract")
			}
		})
	}
}

func TestNativeReportedReasonActualFunction(t *testing.T) {
	// Explicit owned long directory: the test must not rely on an ambient
	// Mac/CI path length. Only regular files and finite shell output are used.
	longTemp := filepath.Join(t.TempDir(), strings.Repeat("x", 120))
	if e := os.Mkdir(longTemp, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TMPDIR", longTemp)
	root, args, opt := nativeFixture(t)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	opt.receipt = filepath.Join(dir, "native.json")
	body := []byte("#!/bin/sh\nprintf 'plugin dial: listen unix %s/plugin42: bind: invalid argument\n' \"$TMPDIR\" >&2\nexit 1\n")
	if e := os.WriteFile(opt.tool, body, 0700); e != nil {
		t.Fatal(e)
	}
	opt.digest, _ = nativeDigest(opt.tool, 160<<20, true)
	opt.run = func(c *exec.Cmd) error { return c.Run() }
	_, e := checkNativeRelease(root, args, opt)
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 1 {
		t.Fatal("reported text changed actual failure")
	}
	b, readErr := os.ReadFile(opt.receipt + ".status")
	if readErr != nil {
		t.Fatal("failure diagnostic missing")
	}
	var d map[string]any
	if e := json.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	if d["reason_hint"] != "reported-plugin-handshake" || d["socket_path_bytes"] != nil || d["tmpdir_bytes"].(float64)+17 > 107 {
		t.Fatal("real function did not classify finite synthetic helper output")
	}
	t.Logf("NATIVE_REPORTED_REASON_FIXTURE:%s", b)
	if bytes.Contains(b, []byte("listen unix")) || bytes.Contains(b, []byte(root)) || len(b) > 512 {
		t.Fatal("raw reported text escaped diagnostic")
	}
}

func TestNativeReportedCaptureBound(t *testing.T) {
	var w nativeReportedOutput
	payload := bytes.Repeat([]byte{'x'}, (16<<10)+1)
	n, e := w.Write(payload)
	if e != nil || n != len(payload) || w.Len() != 16<<10 || !w.overflow {
		t.Fatal("capture is not bounded and accepting")
	}
	if hint, size := classifyNativeReportedError(w.String(), "/inert", w.overflow); hint != "unclassified" || size != nil {
		t.Fatal("truncated capture was classified")
	}
}

// Real entry function, synthetic verifier callback, owned regular directories.
// The deliberately long ambient TMPDIR must not become the socket namespace.
func TestNativeShortTempEntry(t *testing.T) {
	ambient := filepath.Join(t.TempDir(), strings.Repeat("a", 120))
	if e := os.Mkdir(ambient, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TMPDIR", ambient)
	root, args, opt := nativeFixture(t)
	var socketDir string
	calls := 0
	opt.run = func(c *exec.Cmd) error {
		calls++
		nativeEnvironment(t, c, root)
		values := map[string]string{}
		for _, v := range c.Env {
			k, v, _ := strings.Cut(v, "=")
			values[k] = v
		}
		socketDir = values["TMPDIR"]
		if len(socketDir)+len("/plugin")+10 > 107 {
			t.Error("native entry exceeded worst-case Linux socket byte budget")
		}
		if filepath.Dir(values["HOME"]) != socketDir {
			t.Error("native entry did not use its single private root directly for socket temp")
		}
		if strings.HasPrefix(socketDir, ambient) {
			t.Error("native socket namespace inherited long ambient temp path")
		}
		return nil
	}
	if _, e := checkNativeRelease(root, args, opt); e != nil || calls != 1 {
		t.Fatalf("synthetic native entry failed: %v", e)
	}
	if socketDir != "" {
		if _, e := os.Lstat(socketDir); !os.IsNotExist(e) {
			t.Fatal("owned socket directory survived joined return")
		}
	}
}

func nativeOwnedTestParent(t *testing.T) string {
	t.Helper()
	p, e := os.MkdirTemp("/tmp", "nt-")
	if e != nil {
		t.Fatal("cannot create owned native test parent")
	}
	p, e = filepath.EvalSymlinks(p)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := os.Lstat(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("OWNED_NATIVE_PARENT:%s", p)
	t.Cleanup(func() {
		current, e := os.Lstat(p)
		if e != nil || !os.SameFile(identity, current) {
			t.Error("native test parent identity changed; teardown refused")
			return
		}
		if e := os.RemoveAll(p); e != nil {
			t.Error("owned native test parent teardown failed")
			return
		}
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Error("owned native test parent survived teardown")
		}
	})
	return p
}

type nativeSyntheticInfo struct {
	os.FileInfo
	mode os.FileMode
	uid  uint32
}

func (i nativeSyntheticInfo) Mode() os.FileMode { return i.mode }
func (i nativeSyntheticInfo) IsDir() bool       { return i.mode.IsDir() }
func (i nativeSyntheticInfo) Sys() any          { return &syscall.Stat_t{Uid: i.uid} }

func TestNativeWorkspaceBudgetAndParentPolicy(t *testing.T) {
	name := "nc-" + strings.Repeat("A", 22)
	for _, tc := range []struct {
		name, parent string
		ok           bool
	}{
		{"parent64", "/" + strings.Repeat("p", 63), true},
		{"parent65", "/" + strings.Repeat("p", 64), false},
		{"byte-not-rune-budget", "/" + strings.Repeat("p", 62) + "é", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, e := nativeWorkspacePath(tc.parent, name)
			if (e == nil) != tc.ok {
				t.Fatal("native raw-byte path budget mismatch")
			}
			if e == nil && len(path)+17 > 107 {
				t.Fatal("admitted path exceeded budget")
			}
		})
	}
	if _, e := nativeWorkspacePath("/tmp", "../inert"); e == nil {
		t.Fatal("native child traversal accepted")
	}
	info, e := os.Stat(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		uid  uint32
		mode os.FileMode
		ok   bool
	}{
		{"private-actor", 12345, os.ModeDir | 0700, true},
		{"root-sticky", 0, os.ModeDir | os.ModeSticky | 0777, true},
		{"root-read-only-to-others", 0, os.ModeDir | 0755, true},
		{"root-unsafe", 0, os.ModeDir | 0777, false},
		{"foreign-owner", 23456, os.ModeDir | 0700, false},
		{"actor-public", 12345, os.ModeDir | 0777, false},
		{"not-directory", 12345, 0700, false},
		{"redirected", 12345, os.ModeDir | os.ModeSymlink | 0700, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := nativeTempParent(nativeSyntheticInfo{info, tc.mode, tc.uid}, 12345)
			if (e == nil) != tc.ok {
				t.Fatal("native temp parent ownership/isolation policy mismatch")
			}
		})
	}
}

type nativeEntropyFailure struct{ err error }

func (r nativeEntropyFailure) Read([]byte) (int, error) { return 0, r.err }

func TestNativeWorkspaceAllocationAndCleanup(t *testing.T) {
	parent := nativeOwnedTestParent(t)
	if e := os.WriteFile(filepath.Join(parent, "sibling"), []byte("preserve public fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	w, e := newNativeWorkspaceAt(parent, bytes.NewReader(make([]byte, 16)))
	if e != nil {
		t.Fatal("owned workspace creation failed")
	}
	t.Logf("OWNED_NATIVE_TMP:%s", w.path)
	info, e := os.Lstat(w.path)
	if e != nil || !os.SameFile(w.identity, info) || nativePrivateDirectory(info, os.Geteuid()) != nil {
		t.Fatal("native directory is not identity-bound/private")
	}
	if len(w.path)+17 > 107 || filepath.Dir(w.path) != parent {
		t.Fatal("native directory violated containment/budget")
	}
	if e = w.parent.WriteFile(w.name+"/owned", []byte("inert owned child"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = w.cleanup(); e != nil {
		t.Fatal("mandatory identity-bound cleanup failed")
	}
	if _, e = os.Lstat(w.path); !os.IsNotExist(e) {
		t.Fatal("native directory survived cleanup")
	}
	b, e := os.ReadFile(filepath.Join(parent, "sibling"))
	if e != nil || string(b) != "preserve public fixture" {
		t.Fatal("cleanup touched unowned sibling")
	}
	if _, e = w.parent.Lstat("."); e == nil {
		t.Fatal("parent capability was not closed")
	}
	if e = w.cleanup(); e != nil {
		t.Fatal("completed cleanup was not idempotent")
	}
}

func TestNativeWorkspaceEntropyAndCollisionRefusals(t *testing.T) {
	t.Run("entropy", func(t *testing.T) {
		parent := nativeOwnedTestParent(t)
		sentinel := errors.New("inert entropy failure")
		w, e := newNativeWorkspaceAt(parent, nativeEntropyFailure{sentinel})
		if w != nil || !errors.Is(e, sentinel) {
			t.Fatal("entropy failure did not fail closed with identity")
		}
		entries, e := os.ReadDir(parent)
		if e != nil || len(entries) != 0 {
			t.Fatal("entropy failure created output")
		}
	})
	t.Run("collisions", func(t *testing.T) {
		parent := nativeOwnedTestParent(t)
		name := "nc-" + strings.Repeat("A", 22)
		path := filepath.Join(parent, name)
		if e := os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(path, "keep"), []byte("preserve"), 0600); e != nil {
			t.Fatal(e)
		}
		before, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		w, e := newNativeWorkspaceAt(parent, bytes.NewReader(make([]byte, 16*8)))
		if w != nil || e == nil || !strings.Contains(e.Error(), "collision budget") {
			t.Fatal("collision budget did not refuse")
		}
		after, e := os.Lstat(path)
		b, readErr := os.ReadFile(filepath.Join(path, "keep"))
		if e != nil || readErr != nil || !os.SameFile(before, after) || string(b) != "preserve" {
			t.Fatal("collision removed/modified preexisting fixture")
		}
	})
}

func TestNativeWorkspaceIdentityMismatchRefusal(t *testing.T) {
	parent := nativeOwnedTestParent(t)
	w, e := newNativeWorkspaceAt(parent, bytes.NewReader(make([]byte, 16)))
	if e != nil {
		t.Fatal(e)
	}
	if e = w.parent.Rename(w.name, w.name+"-retained"); e != nil {
		t.Fatal(e)
	}
	if e = w.parent.Mkdir(w.name, 0700); e != nil {
		t.Fatal(e)
	}
	if e = w.parent.WriteFile(w.name+"/keep", []byte("replacement fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = w.cleanup(); e == nil {
		t.Fatal("changed native identity was removed")
	}
	b, e := os.ReadFile(filepath.Join(w.path, "keep"))
	if e != nil || string(b) != "replacement fixture" {
		t.Fatal("cleanup touched replacement fixture")
	}
	retained, e := os.Lstat(filepath.Join(parent, w.name+"-retained"))
	if e != nil || !os.SameFile(retained, w.identity) {
		t.Fatal("original retained identity changed")
	}
	if _, e = w.parent.Lstat("."); e == nil {
		t.Fatal("refusal leaked parent capability")
	}
}

func TestNativeWorkspacePartialInitializationCleanup(t *testing.T) {
	root, args, opt := nativeFixture(t)
	factory := opt.workspace
	var owned string
	opt.workspace = func() (*nativeWorkspace, error) {
		w, e := factory()
		if e != nil {
			return w, e
		}
		owned = w.path
		if e := w.parent.Mkdir(w.name+"/h", 0700); e != nil {
			t.Fatal(e)
		}
		return w, nil
	}
	calls := 0
	opt.run = func(*exec.Cmd) error { calls++; return nil }
	_, e := checkNativeRelease(root, args, opt)
	if !errors.Is(e, os.ErrExist) || calls != 0 {
		t.Fatal("partial initialization failed to stop before verifier")
	}
	if _, e := os.Lstat(owned); !os.IsNotExist(e) {
		t.Fatal("partial initialization left owned directory")
	}
}
