//go:build ignore

// Native release post-hook. wfctl v0.78.2 checks identity/version and declared
// IaC services, not complete capability-list parity. Snapshot and cross-target
// builds retain compiler/archive checks without claiming runtime acceptance.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	cleanup            func(string) error
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
	owned, err := os.MkdirTemp("", "compute-native-check-")
	if err != nil {
		return "", errors.New("cannot create owned verifier directory")
	}
	defer func() {
		// Preserve the primary phase even if cleanup independently fails.
		diagnostic.PrimaryPhase = "none"
		if err != nil {
			diagnostic.PrimaryPhase = phase
		}
		diagnostic.Cleanup = "removed"
		if e := opt.cleanup(owned); e != nil {
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
	home, tmp := filepath.Join(owned, "home"), filepath.Join(owned, "tmp")
	if os.Mkdir(home, 0700) != nil || os.Mkdir(tmp, 0700) != nil {
		return "", errors.New("cannot prepare owned verifier environment")
	}
	cmd := exec.Command(opt.tool, "plugin", "verify-capabilities", "--binary", artifact, root)
	cmd.Dir = root
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + tmp, "LANG=C", "LC_ALL=C", "WFCTL_DIFFCACHE=:memory:", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	// No raw plugin output or inherited stdin: only fixed gate diagnostics.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
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
			run:     (*exec.Cmd).Run, cleanup: os.RemoveAll,
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
