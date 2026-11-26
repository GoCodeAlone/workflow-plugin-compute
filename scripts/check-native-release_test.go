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
	opt := nativeCheckOptions{host: "linux/amd64", tool: tool, digest: digest, cleanup: os.RemoveAll, run: func(*exec.Cmd) error { t.Fatal("unexpected process invocation"); return nil }}
	// v2.20.3 base.OptionsForTarget uses filepath.Abs for the actual hook .Path.
	return root, []string{"linux", "amd64", filepath.Join(root, "dist/plugin"), "false"}, opt
}

func nativeEnvironment(t *testing.T, cmd *exec.Cmd, root string) string {
	t.Helper()
	if cmd.Dir != root || cmd.Stdin != nil || cmd.Stdout != io.Discard || cmd.Stderr != io.Discard {
		t.Fatal("cwd or standard streams changed")
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
	if filepath.Dir(values["TMPDIR"]) != owned || owned == root {
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
			opt.cleanup = func(path string) error {
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
				opt.cleanup = func(p string) error {
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
				opt.cleanup = func(p string) error {
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
