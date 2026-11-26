//go:build ignore

// Named-file, stdlib-only controls. Digest/host seams are unit-only; main has
// fixed production policy. No test launches wfctl or an actual plugin binary.
package main

import (
	"bytes"
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
