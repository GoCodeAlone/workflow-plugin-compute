//go:build ignore

// Native release post-hook. wfctl v0.78.2 checks identity/version and declared
// IaC services, not complete capability-list parity. Snapshot and cross-target
// builds retain compiler/archive checks without claiming runtime acceptance.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Immutable official Workflow release v0.78.2, asset 442231027. This binds the
// downloaded bytes to its reviewed GitHub digest; no independent signature is
// claimed. Neither an environment variable nor a CLI flag can change the pin.
const nativeWfctlSHA = "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8"

// Dependencies are explicit for inert unit controls; main supplies fixed host,
// digest and real command/cleanup operations, without a runtime override.
type nativeCheckOptions struct {
	host, tool, digest string
	receipt            string
	run                func(*exec.Cmd) error
	afterCleanup       func(string) error
	workspace          func() (*nativeWorkspace, error)
}

type nativeValidationReceipt struct {
	Schema      int    `json:"schema"`
	Scope       string `json:"scope"`
	Verdict     string `json:"verdict"`
	Target      string `json:"target"`
	Artifact    string `json:"artifact_path"`
	ArtifactSHA string `json:"artifact_sha256"`
	ManifestSHA string `json:"manifest_sha256"`
	VerifierSHA string `json:"verifier_sha256"`
}

// Failure diagnostics are deliberately distinct from an accepted native
// receipt: fixed facts only, with no paths, child output or error strings.
type nativeFailureDiagnostic struct {
	Schema         int    `json:"schema"`
	Scope          string `json:"scope"`
	PrimaryPhase   string `json:"primary_phase"`
	VerifierResult string `json:"verifier_result"`
	Joined         bool   `json:"joined"`
	Exit           *int   `json:"exit,omitempty"`
	Cleanup        string `json:"cleanup"`
	TmpBytes       *int   `json:"tmpdir_bytes,omitempty"`
	ReasonHint     string `json:"reason_hint,omitempty"`
	SocketBytes    *int   `json:"socket_path_bytes,omitempty"`
}

func writeNativeFailureDiagnostic(path string, diagnostic nativeFailureDiagnostic) error {
	b, e := json.Marshal(diagnostic)
	if e != nil {
		return e
	}
	if len(b) > 512 {
		return errors.New("native diagnostic exceeded bound")
	}
	return writeNativeRecord(path, b)
}

func nativeReceiptDestination(root, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("receipt requires a fresh absolute owned path")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("receipt must remain outside source")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("receipt parent must be a private owned directory")
	}
	canonicalRoot, e := filepath.EvalSymlinks(root)
	if e != nil {
		return errors.New("cannot resolve receipt source")
	}
	canonicalParent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return errors.New("cannot resolve receipt parent")
	}
	rel, e = filepath.Rel(canonicalRoot, canonicalParent)
	if e != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("receipt must remain outside source")
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("receipt destination already exists or is unavailable")
	}
	return nil
}

func writeNativeReceipt(path string, receipt nativeValidationReceipt) error {
	b, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return writeNativeRecord(path, b)
}

func writeNativeRecord(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot exclusively create native receipt")
	}
	_, writeErr := f.Write(b)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		removeErr := os.Remove(path) // Only the file just created above is owned.
		return errors.Join(writeErr, closeErr, removeErr)
	}
	return nil
}

func nativeDigest(path string, limit int64, executable bool) (string, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > limit || (executable && st.Mode().Perm()&0111 == 0) {
		return "", errors.New("expected a bounded regular non-symlink file with required mode")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot read validation input")
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n != st.Size() || n > limit {
		return "", errors.New("validation input read/size mismatch")
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func nativeArtifactPath(root, rel string) (string, error) {
	if filepath.Clean(rel) != rel || strings.ContainsAny(rel, "\\\x00\r\n") {
		return "", errors.New("unexpected source/artifact path")
	}
	// v2.20.3 base.OptionsForTarget supplies an absolute .Path. Convert only
	// canonical paths inside this source root; never admit outside artifacts.
	if filepath.IsAbs(rel) {
		var err error
		rel, err = filepath.Rel(root, rel)
		if err != nil {
			return "", errors.New("unexpected source/artifact path")
		}
	}
	if !strings.HasPrefix(rel, "dist/") {
		return "", errors.New("unexpected source/artifact path")
	}
	p := root
	for _, part := range strings.Split(rel, "/") {
		if part == ".." || part == "." || part == "" {
			return "", errors.New("noncanonical source/artifact path")
		}
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("source/artifact path missing or redirected")
		}
	}
	return p, nil
}

func checkNativeRelease(root string, args []string, opt nativeCheckOptions) (result string, err error) {
	if len(args) != 4 || (args[3] != "true" && args[3] != "false") {
		return "", errors.New("expected OS ARCH ARTIFACT SNAPSHOT_BOOL")
	}
	target := args[0] + "/" + args[1]
	if target != "linux/amd64" && target != "darwin/arm64" {
		return "", errors.New("unsupported release target")
	}
	if args[3] == "true" {
		return "snapshot: native runtime check not performed; compiler/archive gates remain", nil
	}
	if target == "darwin/arm64" {
		return "cross target: native runtime check not performed; compiler/archive gates remain", nil
	}
	if opt.host != "linux/amd64" {
		return "", errors.New("native release verification requires a linux/amd64 host")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", errors.New("cannot resolve project root")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("cannot resolve project root")
	}
	phase := "artifact"
	diagnostic := nativeFailureDiagnostic{Schema: 1, Scope: "native-hook-diagnostic", VerifierResult: "not-invoked", Cleanup: "not-created"}
	if opt.receipt != "" {
		// Both names must be fresh before installing reporting. Resolve parent
		// placement so neither receipt can redirect into the source tree.
		if err = nativeReceiptDestination(root, opt.receipt); err != nil {
			return "", err
		}
		if err = nativeReceiptDestination(root, opt.receipt+".status"); err != nil {
			return "", err
		}
		defer func() {
			if err == nil {
				return
			}
			if diagnostic.PrimaryPhase == "" {
				diagnostic.PrimaryPhase = phase
			}
			if e := writeNativeFailureDiagnostic(opt.receipt+".status", diagnostic); e != nil {
				err = errors.Join(err, fmt.Errorf("native diagnostic failed: %w", e))
				result = ""
			}
		}()
	}
	artifact, err := nativeArtifactPath(root, args[2])
	if err != nil {
		return "", err
	}
	manifest := filepath.Join(root, "plugin.json")
	phase = "tool"
	if !filepath.IsAbs(opt.tool) || filepath.Clean(opt.tool) != opt.tool {
		return "", errors.New("WFCTL_BIN must be an absolute verifier path")
	}
	toolSHA, err := nativeDigest(opt.tool, 160<<20, true)
	if err != nil || toolSHA != opt.digest {
		return "", errors.New("wfctl authentication failed")
	}
	phase = "artifact"
	artifactSHA, err := nativeDigest(artifact, 128<<20, true)
	if err != nil {
		return "", fmt.Errorf("artifact validation failed: %w", err)
	}
	phase = "manifest"
	manifestSHA, err := nativeDigest(manifest, 64<<10, false)
	if err != nil {
		return "", fmt.Errorf("manifest validation failed: %w", err)
	}
	phase = "receipt-destination"
	if opt.receipt != "" {
		if err = nativeReceiptDestination(root, opt.receipt); err != nil {
			return "", err
		}
	}
	phase = "workspace"
	makeWorkspace := opt.workspace
	if makeWorkspace == nil {
		makeWorkspace = newNativeWorkspace
	}
	workspace, err := makeWorkspace()
	if err != nil || workspace == nil {
		return "", errors.Join(errors.New("cannot create owned short verifier directory"), err)
	}
	owned := workspace.path

	defer func() {
		// Preserve the primary phase even if cleanup independently fails.
		diagnostic.PrimaryPhase = "none"
		if err != nil {
			diagnostic.PrimaryPhase = phase
		}
		diagnostic.Cleanup = "removed"
		cleanupErr := workspace.cleanup()
		// Optional synthetic post-cleanup check; production never substitutes
		// the mandatory identity-bound cleanup with a caller-supplied remover.
		if cleanupErr == nil && opt.afterCleanup != nil {
			cleanupErr = opt.afterCleanup(owned)
		}
		if e := cleanupErr; e != nil {
			diagnostic.Cleanup = "failed"
			err = errors.Join(err, fmt.Errorf("owned verifier cleanup failed: %w", e))
			result = ""
		}
		// A receipt is a success record only after the child joined, every
		// input remained stable and owned temporary cleanup succeeded.
		if err == nil && opt.receipt != "" {
			rel, e := filepath.Rel(root, artifact)
			if e == nil {
				e = writeNativeReceipt(opt.receipt, nativeValidationReceipt{Schema: 1, Scope: "runtime-identity-version-declared-iac", Verdict: "pass", Target: "linux-amd64", Artifact: filepath.ToSlash(rel), ArtifactSHA: artifactSHA, ManifestSHA: manifestSHA, VerifierSHA: toolSHA})
			}
			if e != nil {
				diagnostic.PrimaryPhase = "receipt"
				err, result = fmt.Errorf("native receipt failed: %w", e), ""
			}
		}
	}()
	home, tmp := filepath.Join(owned, "h"), owned
	if e := workspace.parent.Mkdir(workspace.name+"/h", 0700); e != nil {
		return "", fmt.Errorf("cannot prepare owned verifier HOME: %w", e)
	}
	homeInfo, e := workspace.parent.Lstat(workspace.name + "/h")
	if e != nil {
		return "", fmt.Errorf("cannot verify owned verifier HOME: %w", e)
	}
	if e = nativePrivateDirectory(homeInfo, os.Geteuid()); e != nil {
		return "", e
	}
	cmd := exec.Command(opt.tool, "plugin", "verify-capabilities", "--binary", artifact, root)
	cmd.Dir = root
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + tmp, "LANG=C", "LC_ALL=C", "WFCTL_DIFFCACHE=:memory:", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	// No raw plugin output or inherited stdin: only fixed gate diagnostics.
	var reported nativeReportedOutput
	cmd.Stdout, cmd.Stderr = io.Discard, &reported
	phase = "verifier"
	n := len(tmp)
	diagnostic.TmpBytes = &n // Exactly the TMPDIR supplied above.
	runErr := opt.run(cmd)
	switch {
	case cmd.ProcessState != nil:
		diagnostic.VerifierResult = "exited"
		diagnostic.Joined = true
		code := cmd.ProcessState.ExitCode()
		diagnostic.Exit = &code
	case cmd.Process == nil:
		diagnostic.VerifierResult = "not-started"
	default:
		diagnostic.VerifierResult = "state-unavailable"
	}
	if runErr != nil && diagnostic.Joined && diagnostic.Exit != nil && *diagnostic.Exit > 0 {
		diagnostic.ReasonHint, diagnostic.SocketBytes = classifyNativeReportedError(reported.String(), tmp, reported.overflow)
	}
	if runErr != nil {
		return "", fmt.Errorf("runtime identity/version/declared-IaC verifier failed: %w", runErr)
	}
	phase = "postcheck"
	for _, input := range []struct {
		path, before string
		limit        int64
		executable   bool
	}{{opt.tool, toolSHA, 160 << 20, true}, {artifact, artifactSHA, 128 << 20, true}, {manifest, manifestSHA, 64 << 10, false}} {
		after, e := nativeDigest(input.path, input.limit, input.executable)
		if e != nil || after != input.before {
			return "", errors.New("verifier, artifact or manifest changed during validation")
		}
	}
	return "native runtime identity/version and declared IaC verified; full capability parity not asserted", nil
}

func main() {
	root, err := os.Getwd()
	if err == nil {
		var result string
		result, err = checkNativeRelease(root, os.Args[1:], nativeCheckOptions{
			host: runtime.GOOS + "/" + runtime.GOARCH, tool: os.Getenv("WFCTL_BIN"), digest: nativeWfctlSHA,
			receipt: os.Getenv("NATIVE_CHECK_RECEIPT"),
			run:     (*exec.Cmd).Run, workspace: newNativeWorkspace,
		})
		if err == nil {
			fmt.Println(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "native release check:", err)
		os.Exit(1)
	}
}

// The classifier consumes untrusted reported text, not kernel evidence. The
// exact authenticated wfctl can embed plugin stderr. Only fixed hints and a
// validated byte count are retained; no capture bytes ever enter diagnostics.
type nativeReportedOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *nativeReportedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (16 << 10) - w.Len()
	if left > 0 {
		w.Buffer.Write(p[:min(left, n)])
	}
	if n > left {
		w.overflow = true
	}
	return n, nil
}

func classifyNativeReportedError(text, tmp string, overflow bool) (string, *int) {
	unknown := func() (string, *int) { return "unclassified", nil }
	if overflow || !utf8.ValidString(text) || strings.ContainsRune(text, '\x00') || !filepath.IsAbs(tmp) || strings.ContainsAny(tmp, "\r\n\x00") {
		return unknown()
	}
	// These prefixes come from pinned wfctl v0.78.2. Expected wrapper nesting
	// is recognized; conflicting independent categories remain unclassified.
	patterns := []struct{ pattern, kind string }{
		{`(?m)^(?:error: |wfctl: )?(?:plugin dial:|timeout waiting for plugin handshake)`, "reported-plugin-handshake"},
		{`(?m)^(?:error: |wfctl: )?plugin[.]json parse:`, "reported-manifest-parse"},
		{`(?m)^(?:error: |wfctl: )?plugin[.]json validate:`, "reported-manifest-validation"},
		{`(?m)^(?:error: |wfctl: )?GetManifest RPC:`, "reported-manifest-rpc"},
		{`(?m)^(?:error: |wfctl: )?GetContractRegistry RPC:`, "reported-contract-rpc"},
		{`(?m)^(?:error: |wfctl: )?verify-capabilities: [1-9][0-9]{0,3} mismatch[(]es[)]:`, "reported-manifest-mismatch"},
	}
	kind := ""
	matches := 0
	for _, p := range patterns {
		n := len(regexp.MustCompile(p.pattern).FindAllStringIndex(text, -1))
		if n > 0 {
			kind = p.kind
			matches += n
		}
	}
	if matches > 1 {
		return unknown()
	}
	if strings.Contains(text, "listen unix ") {
		if strings.Count(text, "listen unix ") != 1 {
			return unknown()
		}
		pattern := `(?:^|[ \t\r\n"(=:])listen unix (` + regexp.QuoteMeta(tmp+"/plugin") + `([0-9]{1,10})): bind: invalid argument(?:$|[\r\n" )])`
		m := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if len(m) != 3 {
			return unknown()
		}
		n, e := strconv.ParseUint(m[2], 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != m[2] {
			return unknown()
		}
		// Linux/amd64 RawSockaddrUnix.Path is108bytes, including the required
		// terminator for this non-abstract pathname. No socket syscall occurs here.
		if len(m[1]) > 107 {
			if kind != "" && kind != "reported-plugin-handshake" {
				return unknown()
			}
			size := len(m[1])
			return "reported-unix-socket-path-length", &size
		}
	}
	if kind != "" {
		return kind, nil
	}
	return unknown()
}

// A single private root is the exact TMPDIR handed to wfctl. The default
// go-plugin Unix basename is /plugin plus at most ten uint32 decimal digits.
const nativeSocketSuffixMax = len("/plugin") + 10

type nativeWorkspace struct {
	parent     *os.Root
	name, path string
	identity   os.FileInfo
	closed     bool
	cleanupErr error
}

func nativeWorkspacePath(parent, name string) (string, error) {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent || !regexp.MustCompile(`^nc-[A-Za-z0-9_-]{22}$`).MatchString(name) {
		return "", errors.New("noncanonical native workspace name")
	}
	path := filepath.Join(parent, name)
	if len(path)+nativeSocketSuffixMax > 107 {
		return "", errors.New("native workspace exceeds Linux Unix-socket byte budget")
	}
	return path, nil
}

func nativeDirectoryOwner(info os.FileInfo) (int, error) {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("native workspace is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("native directory ownership unavailable")
	}
	return int(stat.Uid), nil
}
func nativePrivateDirectory(info os.FileInfo, uid int) error {
	owner, e := nativeDirectoryOwner(info)
	if e != nil {
		return e
	}
	if owner != uid || info.Mode().Perm() != 0700 {
		return errors.New("native workspace must be owned and mode0700")
	}
	return nil
}
func nativeTempParent(info os.FileInfo, uid int) error {
	owner, e := nativeDirectoryOwner(info)
	if e != nil {
		return e
	}
	if owner == uid && info.Mode().Perm() == 0700 {
		return nil
	}
	if owner != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
		return errors.New("native temp parent lacks trusted ownership/isolation")
	}
	return nil
}

func newNativeWorkspace() (*nativeWorkspace, error) { return newNativeWorkspaceAt("/tmp", rand.Reader) }

// The path/entropy parameters are private test seams. main always selects the
// fixed /tmp factory and crypto/rand; there is no environment/CLI override.
func newNativeWorkspaceAt(base string, entropy io.Reader) (workspace *nativeWorkspace, err error) {
	canonical, e := filepath.EvalSymlinks(base)
	if e != nil {
		return nil, fmt.Errorf("cannot resolve native temp parent: %w", e)
	}
	canonical, e = filepath.Abs(canonical)
	if e != nil {
		return nil, e
	}
	anchor, e := os.OpenRoot(canonical)
	if e != nil {
		return nil, fmt.Errorf("cannot open native temp parent: %w", e)
	}
	transferred := false
	defer func() {
		if !transferred {
			err = errors.Join(err, anchor.Close())
		}
	}()
	info, e := anchor.Lstat(".")
	if e != nil {
		return nil, e
	}
	if e = nativeTempParent(info, os.Geteuid()); e != nil {
		return nil, e
	}
	byPath, e := os.Lstat(canonical)
	if e != nil || !os.SameFile(info, byPath) {
		return nil, errors.New("native temp parent path/descriptor mismatch")
	}
	if _, e = nativeWorkspacePath(canonical, "nc-"+strings.Repeat("A", 22)); e != nil {
		return nil, e
	}
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, e = io.ReadFull(entropy, nonce[:]); e != nil {
			return nil, fmt.Errorf("native workspace entropy failed: %w", e)
		}
		name := "nc-" + base64.RawURLEncoding.EncodeToString(nonce[:])
		path, e := nativeWorkspacePath(canonical, name)
		if e != nil {
			return nil, e
		}
		if e = anchor.Mkdir(name, 0700); os.IsExist(e) {
			continue
		} else if e != nil {
			return nil, fmt.Errorf("native workspace creation failed: %w", e)
		}
		child, e := anchor.Lstat(name)
		owner, ownerErr := nativeDirectoryOwner(child)
		if e != nil || ownerErr != nil || owner != os.Geteuid() {
			// No identity was admitted: close the capability and retain the entry
			// rather than deleting an entry that might no longer be ours.
			return nil, errors.Join(errors.New("new native workspace identity unavailable; possible residue retained"), e, ownerErr)
		}
		workspace = &nativeWorkspace{parent: anchor, name: name, path: path, identity: child}
		transferred = true
		admissionErr := nativePrivateDirectory(child, os.Geteuid())
		actual, pathErr := os.Lstat(path)
		if pathErr != nil || !os.SameFile(child, actual) {
			admissionErr = errors.Join(admissionErr, errors.New("native child path/descriptor mismatch"), pathErr)
		}
		if admissionErr != nil {
			return nil, errors.Join(admissionErr, workspace.cleanup())
		}
		return workspace, nil
	}
	return nil, errors.New("native workspace collision budget exhausted")
}

func (w *nativeWorkspace) cleanup() (err error) {
	if w.closed {
		return w.cleanupErr
	}
	w.closed = true
	defer func() { err = errors.Join(err, w.parent.Close()); w.cleanupErr = err }()
	current, e := w.parent.Lstat(w.name)
	if e != nil || !os.SameFile(w.identity, current) {
		return errors.New("native workspace identity changed; cleanup refused, residue retained")
	}
	owner, e := nativeDirectoryOwner(current)
	if e != nil || owner != os.Geteuid() {
		return errors.New("native workspace owner changed; cleanup refused, residue retained")
	}
	byPath, e := os.Lstat(w.path)
	if e != nil || !os.SameFile(current, byPath) {
		return errors.New("native workspace path changed; cleanup refused, residue retained")
	}
	privacyErr := nativePrivateDirectory(current, os.Geteuid())
	if e = w.parent.RemoveAll(w.name); e != nil {
		return errors.Join(privacyErr, fmt.Errorf("native owned removal failed: %w", e))
	}
	if _, e = w.parent.Lstat(w.name); !os.IsNotExist(e) {
		return errors.Join(privacyErr, errors.New("native workspace remains after cleanup"))
	}
	return privacyErr
}
