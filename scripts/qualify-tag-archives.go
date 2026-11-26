//go:build ignore

// Read-only PR qualification driver. No configurable engine argv, publishing
// credentials, remote tags or artifact uploads. Real tag-mode execution is
// qualified only when this exact command runs on the hosted Linux runner.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
)

const tagEngineSHA = "d124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d"
const tagWfctlSHA = "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8"

var tagFullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

type tagQualification struct {
	sha, tree, root, source, engine, wfctl, goBin string
	run                                           func(string, []string, []string) ([]byte, error)
}

func fixedTagRelease(engine string) []string {
	return []string{engine, "release", "--config=.goreleaser.yaml", "--clean", "--skip=publish,announce,sign,notarize,sbom,docker,ko,changelog", "--parallelism=1", "--timeout=10m"}
}

func tagFileHash(path string, max int64, executable bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("noncanonical tool path")
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > max || (executable && st.Mode().Perm()&0111 == 0) {
		return "", errors.New("invalid qualification file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("qualification file unreadable")
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil || n != st.Size() || n > max {
		return "", errors.New("qualification file changed/oversized")
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (q tagQualification) environment(native bool) []string {
	e := []string{"PATH=" + filepath.Dir(q.goBin) + ":" + filepath.Dir(q.engine) + ":/usr/bin:/bin", "HOME=" + filepath.Join(q.root, "execution-home"), "TMPDIR=" + filepath.Join(q.root, "execution-tmp"), "LANG=C", "LC_ALL=C", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOAUTH=off", "GOTELEMETRY=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GOPACKAGESDRIVER=off", "CGO_ENABLED=0", "GOFLAGS=-p=1", "GOMAXPROCS=2", "GOMEMLIMIT=768MiB", "GOPATH=" + filepath.Join(q.root, "gopath"), "GOMODCACHE=" + filepath.Join(q.root, "module-cache"), "GOCACHE=" + filepath.Join(q.root, "build-cache"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=file", "GIT_NO_LAZY_FETCH=1"}
	if native {
		e = append(e, "WFCTL_BIN="+q.wfctl, "NATIVE_CHECK_RECEIPT="+filepath.Join(q.root, "native.json"))
	}
	return e
}

func tagGit(dir string, args ...string) []string {
	return append([]string{"/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", "-c", "submodule.recurse=false", "-C", dir}, args...)
}

// Each child is sequentially joined. Raw output is bounded and withheld;
// no private dependency paths or arbitrary diagnostics are logged.
func runTagChild(dir string, env, argv []string) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	var out, errout tagBoundedOutput
	cmd.Stdout, cmd.Stderr = &out, &errout
	e := cmd.Run()
	if e != nil {
		if exit, ok := e.(*exec.ExitError); ok {
			return nil, fmt.Errorf("qualification subprocess failed (exit %d); output withheld%s", exit.ExitCode(), tagNativeDiagnostic(dir, env))
		}
		return nil, fmt.Errorf("qualification subprocess could not start; output withheld%s", tagNativeDiagnostic(dir, env))
	}
	if out.overflow || errout.overflow {
		return nil, errors.New("qualification subprocess output limit exceeded; output withheld")
	}
	return out.Bytes(), nil
}

// Diagnostic-only wire. It never authorizes an artifact or changes failure.
type tagNativeStatus struct {
	Schema         int    `json:"schema"`
	Scope          string `json:"scope"`
	PrimaryPhase   string `json:"primary_phase"`
	VerifierResult string `json:"verifier_result"`
	Joined         bool   `json:"joined"`
	Exit           *int   `json:"exit,omitempty"`
	Cleanup        string `json:"cleanup"`
	TmpBytes       *int   `json:"tmpdir_bytes,omitempty"`
}

func tagNativeDiagnostic(source string, env []string) string {
	receipt := ""
	count := 0
	for _, v := range env {
		if bytes.HasPrefix([]byte(v), []byte("NATIVE_CHECK_RECEIPT=")) {
			receipt = v[len("NATIVE_CHECK_RECEIPT="):]
			count++
		}
	}
	if count == 0 {
		return ""
	}
	prefix := `; native diagnostic=`
	unusable := prefix + `{"observation":"unusable"}`
	if count != 1 || !filepath.IsAbs(receipt) || filepath.Clean(receipt) != receipt {
		return unusable
	}
	parent := filepath.Dir(receipt)
	st, e := os.Lstat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return unusable
	}
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil {
		return unusable
	}
	canonicalSource, e := filepath.EvalSymlinks(source)
	if e != nil {
		return unusable
	}
	rel, e := filepath.Rel(canonicalSource, resolved)
	if e != nil || (rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator)))) {
		return unusable
	}
	path := receipt + ".status"
	st, e = os.Lstat(path)
	if os.IsNotExist(e) {
		return prefix + `{"observation":"not-observed"}`
	}
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 512 {
		return unusable
	}
	f, e := os.Open(path)
	if e != nil {
		return unusable
	}
	b, e := io.ReadAll(io.LimitReader(f, 513))
	closeErr := f.Close()
	if e != nil || closeErr != nil || int64(len(b)) != st.Size() || len(b) > 512 {
		return unusable
	}
	var d tagNativeStatus
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return unusable
	}
	canonical, e := json.Marshal(d)
	if e != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) {
		return unusable
	} // Also rejects duplicate keys/trailing data.
	phases := map[string]bool{"none": true, "artifact": true, "tool": true, "manifest": true, "receipt-destination": true, "workspace": true, "verifier": true, "postcheck": true, "receipt": true}
	cleanups := map[string]bool{"not-created": true, "removed": true, "failed": true}
	if d.Schema != 1 || d.Scope != "native-hook-diagnostic" || !phases[d.PrimaryPhase] || !cleanups[d.Cleanup] || (d.PrimaryPhase == "none" && d.Cleanup != "failed") {
		return unusable
	}
	if d.TmpBytes != nil && (*d.TmpBytes <= 0 || *d.TmpBytes > 4096) {
		return unusable
	}
	switch d.VerifierResult {
	case "not-invoked":
		if d.Joined || d.Exit != nil || d.TmpBytes != nil {
			return unusable
		}
	case "not-started", "state-unavailable":
		if d.Joined || d.Exit != nil || d.TmpBytes == nil {
			return unusable
		}
	case "exited":
		if !d.Joined || d.Exit == nil || *d.Exit < -1 || *d.Exit > 255 || d.TmpBytes == nil {
			return unusable
		}
	default:
		return unusable
	}
	// All values here have been validated against fixed enums/integer bounds.
	out, _ := json.Marshal(struct {
		Observation string          `json:"observation"`
		Facts       tagNativeStatus `json:"facts"`
	}{"refused", d})
	return prefix + string(out)
}

type tagBoundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *tagBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (1 << 20) - w.Len()
	if left > 0 {
		w.Buffer.Write(p[:min(left, n)])
	}
	if n > left {
		w.overflow = true
	}
	return n, nil
}

func tagWrite(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("qualification receipt already exists/unavailable")
	}
	_, we := f.Write(data)
	ce := f.Close()
	return errors.Join(we, ce)
}

func (q tagQualification) prepareClone() (string, error) {
	env := q.environment(false)
	src := filepath.Join(q.root, "source")
	if _, e := os.Lstat(src); !os.IsNotExist(e) {
		return "", errors.New("owned source destination must be fresh")
	}
	// --no-local uses a fresh file-transport pack, not shared objects/hardlinks.
	if _, e := q.run(q.source, env, tagGit(q.source, "clone", "--no-local", "--no-hardlinks", "--no-tags", "--no-checkout", q.source, src)); e != nil {
		return "", e
	}
	if _, e := os.Lstat(filepath.Join(src, ".git/objects/info/alternates")); !os.IsNotExist(e) {
		return "", errors.New("clone has unsupported alternates")
	}
	if _, e := q.run(src, env, tagGit(src, "checkout", "--detach", q.sha)); e != nil {
		return "", e
	}
	head, e := os.ReadFile(filepath.Join(src, ".git/HEAD"))
	if e != nil || string(head) != q.sha+"\n" {
		return "", errors.New("owned checkout must be detached")
	}
	b, e := q.run(src, env, tagGit(src, "rev-parse", "HEAD", "HEAD^{tree}"))
	if e != nil || string(b) != q.sha+"\n"+q.tree+"\n" {
		return "", errors.New("owned checkout source/tree mismatch")
	}
	b, e = q.run(src, env, tagGit(src, "tag", "--list"))
	if e != nil || len(bytes.TrimSpace(b)) != 0 {
		return "", errors.New("owned checkout must not import tags")
	}
	// Canonical public metadata is needed by SCM defaults. It is not fetched;
	// all Git transports except local file remain disabled, and push is inert.
	if _, e = q.run(src, env, tagGit(src, "remote", "set-url", "origin", "https://github.com/GoCodeAlone/workflow-plugin-compute.git")); e != nil {
		return "", e
	}
	if _, e = q.run(src, env, tagGit(src, "config", "remote.origin.pushurl", "disabled://qualification")); e != nil {
		return "", e
	}
	if _, e = q.run(src, env, tagGit(src, "tag", "--no-sign", "v0.0.0-qualification.g"+q.sha, q.sha)); e != nil {
		return "", e
	}
	return src, nil
}

func (q tagQualification) execute(out io.Writer) error {
	if !tagFullSHA.MatchString(q.sha) || !tagFullSHA.MatchString(q.tree) {
		return errors.New("invalid expected source identity")
	}
	for _, p := range []string{q.root, q.source, q.engine, q.wfctl, q.goBin} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("qualification paths must be canonical/absolute")
		}
	}
	st, e := os.Lstat(q.root)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("qualification root must be private and owned")
	}
	for _, name := range []string{"execution-home", "execution-tmp", "module-cache", "build-cache", "gopath"} {
		st, e := os.Lstat(filepath.Join(q.root, name))
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("qualification directories missing/redirected")
		}
	}
	for _, name := range []string{"before.json", "native.json", "native.json.status", "archives.json", "combined.json"} {
		if _, e := os.Lstat(filepath.Join(q.root, name)); !os.IsNotExist(e) {
			return errors.New("qualification receipts must be fresh")
		}
	}
	markerPath := filepath.Join(q.root, "credentials-removed")
	if _, e := tagFileHash(markerPath, 16, false); e != nil {
		return errors.New("credential-removal prerequisite missing")
	}
	marker, e := os.ReadFile(markerPath)
	if e != nil || string(marker) != "removed\n" {
		return errors.New("credential-removal prerequisite missing")
	}
	authConfigs, e := filepath.Glob(filepath.Join(q.root, "auth.*", ".gitconfig"))
	if e != nil || len(authConfigs) != 0 {
		return errors.New("acquisition credential files remain")
	}
	for _, name := range []string{"github_token", "gitlab_token", "gitea_token"} {
		if _, e := os.Lstat(filepath.Join(q.root, "execution-home/.config/goreleaser", name)); !os.IsNotExist(e) {
			return errors.New("execution HOME contains credential material")
		}
	}
	if h, e := tagFileHash(q.engine, 128<<20, true); e != nil || h != tagEngineSHA {
		return errors.New("engine authentication failed")
	}
	if h, e := tagFileHash(q.wfctl, 160<<20, true); e != nil || h != tagWfctlSHA {
		return errors.New("wfctl authentication failed")
	}
	if _, e := tagFileHash(q.goBin, 128<<20, true); e != nil {
		return errors.New("Go tool unavailable")
	}
	b, e := q.run(q.source, q.environment(false), []string{q.goBin, "version"})
	if e != nil || string(b) != "go version go1.27.4 linux/amd64\n" {
		return errors.New("unexpected Go toolchain")
	}
	b, e = q.run(q.source, q.environment(false), tagGit(q.source, "rev-parse", "HEAD", "HEAD^{tree}"))
	if e != nil || string(b) != q.sha+"\n"+q.tree+"\n" {
		return errors.New("input source/tree mismatch")
	}
	src, e := q.prepareClone()
	if e != nil {
		return fmt.Errorf("owned checkout preparation failed: %w", e)
	}
	tag := "v0.0.0-qualification.g" + q.sha
	checker := filepath.Join(src, "scripts/check-release-archives.go")
	goCheck := func(args ...string) ([]byte, error) {
		return q.run(src, q.environment(false), append([]string{q.goBin, "run", checker}, args...))
	}
	if _, e = goCheck("capture-tag", q.sha, q.tree, tag, filepath.Join(q.root, "before.json")); e != nil {
		return fmt.Errorf("tag source capture failed: %w", e)
	}
	for _, phase := range []struct {
		name string
		argv []string
	}{
		{"configuration check", []string{q.engine, "check", "--config=.goreleaser.yaml"}},
		{"nonpublishing tag build", fixedTagRelease(q.engine)},
	} {
		if h, e := tagFileHash(q.engine, 128<<20, true); e != nil || h != tagEngineSHA {
			return errors.New("engine changed before execution")
		}
		if _, e = q.run(src, q.environment(true), phase.argv); e != nil {
			return fmt.Errorf("%s failed: %w", phase.name, e)
		}
	}
	b, e = goCheck("verify-tag", q.sha, q.tree, tag, filepath.Join(q.root, "before.json"), filepath.Join(q.root, "extracted"))
	if e != nil {
		return fmt.Errorf("tag archive verification failed: %w", e)
	}
	if e = tagWrite(filepath.Join(q.root, "archives.json"), b); e != nil {
		return e
	}
	b, e = goCheck("bind-native", q.sha, q.tree, tag, filepath.Join(q.root, "archives.json"), filepath.Join(q.root, "native.json"))
	if e != nil {
		return fmt.Errorf("native/archive receipt binding failed: %w", e)
	}
	if !json.Valid(b) {
		return errors.New("combined receipt is not JSON")
	}
	if e = tagWrite(filepath.Join(q.root, "combined.json"), b); e != nil {
		return e
	}
	_, e = out.Write(b)
	return e
}

func main() {
	if len(os.Args) != 8 {
		fmt.Fprintln(os.Stderr, "usage: qualify-tag-archives SHA TREE OWNED_ROOT SOURCE ENGINE WFCTL GO")
		os.Exit(1)
	}
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "RELEASES_TOKEN", "ACTIONS_RUNTIME_TOKEN", "SSH_AUTH_SOCK", "GORELEASER_CURRENT_TAG", "GORELEASER_PREVIOUS_TAG"} {
		if _, ok := os.LookupEnv(key); ok {
			fmt.Fprintln(os.Stderr, "tag qualification: credential/tag override environment refused")
			os.Exit(1)
		}
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || runtime.Version() != "go1.27.4" || os.Getenv("GOTOOLCHAIN") != "local" {
		fmt.Fprintln(os.Stderr, "tag qualification: requires local Go1.27.4 linux/amd64")
		os.Exit(1)
	}
	a := os.Args[1:]
	q := tagQualification{sha: a[0], tree: a[1], root: a[2], source: a[3], engine: a[4], wfctl: a[5], goBin: a[6], run: runTagChild}
	if e := q.execute(os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "tag qualification:", e)
		os.Exit(1)
	}
}
