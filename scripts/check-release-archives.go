//go:build ignore

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	archivePlugin   = "workflow-plugin-compute"
	archiveModule   = "github.com/GoCodeAlone/" + archivePlugin
	archiveCompiler = "go1.27.4"
	maxBinary       = 128 << 20
	maxManifest     = 64 << 10
	maxMetadata     = 1 << 20
	maxSourceFile   = 4 << 20
)

var targets = []string{"linux-amd64", "darwin-arm64"}
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sumSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var semverBase = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var paxTimestamp = regexp.MustCompile(`^-?[0-9]{1,19}(\.[0-9]{1,9})?$`)

func archiveName(target string) string { return archivePlugin + "-" + target + ".tar.gz" }
func byteHash(b []byte) string         { return fmt.Sprintf("%x", sha256.Sum256(b)) }

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.n += int64(n)
	return n, e
}

type zeroPadding struct{}

func (zeroPadding) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, fmt.Errorf("nonzero bytes after tar end")
		}
	}
	return len(p), nil
}

// A complete first gzip member and its trailer must be consumed. tar EOF and
// gzip.Close alone do not validate a trailer or exclude concatenated members.
func readArchive(in io.Reader, limit int64) (map[string][]byte, error) {
	br := bufio.NewReader(in)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	gz.Multistream(false)
	lr := &io.LimitedReader{R: gz, N: limit + 1}
	cr := &countingReader{r: lr}
	tr := tar.NewReader(cr)
	files := map[string][]byte{}
	var lastEnd int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		// tar.Reader consumes extension headers transparently. The upstream
		// standard tar writer may emit timestamp-only PAX records; accept those
		// explicitly, not arbitrary path/size/link overrides or GNU extensions.
		if h.Format != tar.FormatUSTAR && h.Format != tar.FormatPAX {
			return nil, fmt.Errorf("unsupported tar format")
		}
		for key, value := range h.PAXRecords {
			if (key != "mtime" && key != "atime" && key != "ctime") || !paxTimestamp.MatchString(value) {
				return nil, fmt.Errorf("unreviewed PAX metadata")
			}
		}
		cap := int64(maxBinary)
		if h.Name == "plugin.json" {
			cap = maxManifest
		}
		if (h.Name != archivePlugin && h.Name != "plugin.json") || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > cap || files[h.Name] != nil {
			return nil, fmt.Errorf("unexpected archive member")
		}
		b, e := io.ReadAll(tr)
		if e != nil {
			return nil, e
		}
		if int64(len(b)) != h.Size {
			return nil, fmt.Errorf("short archive member")
		}
		files[h.Name] = b
		lastEnd = cr.n + (512-h.Size%512)%512
	}
	if len(files) != 2 || cr.n < lastEnd+1024 {
		return nil, fmt.Errorf("missing members or tar end markers")
	}
	if _, err = io.Copy(zeroPadding{}, cr); err != nil {
		return nil, err
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("archive exceeds decoded limit")
	}
	if err = gz.Close(); err != nil {
		return nil, err
	}
	if _, err = br.ReadByte(); err != io.EOF {
		return nil, fmt.Errorf("extra gzip member or trailing bytes")
	}
	return files, nil
}

func parseChecksums(b []byte) (map[string]string, error) {
	rows := strings.Split(string(b), "\n")
	if len(rows) != 3 || rows[2] != "" {
		return nil, fmt.Errorf("expected exactly two checksum rows")
	}
	want := map[string]bool{archiveName(targets[0]): true, archiveName(targets[1]): true}
	got := map[string]string{}
	for _, line := range rows[:2] {
		if len(line) < 67 || line[64:66] != "  " || !sumSHA.MatchString(line[:64]) || !want[line[66:]] || got[line[66:]] != "" {
			return nil, fmt.Errorf("invalid or duplicate archive checksum")
		}
		got[line[66:]] = line[:64]
	}
	return got, nil
}

// Reject duplicate keys at every depth instead of allowing JSON's last value
// to silently override the field used by another consumer.
func jsonValue(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var parse func(int) (any, error)
	parse = func(depth int) (any, error) {
		if depth > 32 {
			return nil, fmt.Errorf("JSON nesting limit")
		}
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		v, delim := t.(json.Delim)
		if !delim {
			return t, nil
		}
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("object key")
				}
				if _, ok = m[s]; ok {
					return nil, fmt.Errorf("duplicate JSON key")
				}
				x, e := parse(depth + 1)
				if e != nil {
					return nil, e
				}
				m[s] = x
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("object end")
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				x, e := parse(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("array end")
			}
			return a, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	}
	v, e := parse(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return v, nil
}

func decodeExact(b []byte, out any) error {
	if _, e := jsonValue(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func sameManifest(before, after []byte, version string) error {
	x, e := jsonValue(before)
	if e != nil {
		return e
	}
	y, e := jsonValue(after)
	if e != nil {
		return e
	}
	a, ok := x.(map[string]any)
	if !ok {
		return fmt.Errorf("manifest must be object")
	}
	b, ok := y.(map[string]any)
	if !ok {
		return fmt.Errorf("manifest must be object")
	}
	if v, ok := a["version"].(string); !ok || v == "" {
		return fmt.Errorf("original version missing")
	}
	if b["version"] != version || version == "" {
		return fmt.Errorf("snapshot manifest version mismatch")
	}
	a["version"] = version
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("manifest changed beyond version")
	}
	return nil
}

func checkSnapshotVersion(version, sha string) error {
	i := strings.LastIndex(version, "-SNAPSHOT-")
	if !fullSHA.MatchString(sha) || i < 0 || !semverBase.MatchString(version[:i]) {
		return fmt.Errorf("invalid snapshot version/source")
	}
	short := version[i+len("-SNAPSHOT-"):]
	if len(short) < 7 || len(short) > 40 || !strings.HasPrefix(sha, short) {
		return fmt.Errorf("snapshot not bound to source commit")
	}
	return nil
}

func checkArchiveInfo(info *debug.BuildInfo, target, sha, version string) error {
	if info == nil || info.GoVersion != archiveCompiler || info.Path != archiveModule+"/cmd/"+archivePlugin || info.Main.Path != archiveModule {
		return fmt.Errorf("wrong compiler, command or module")
	}
	s := map[string]string{}
	for _, x := range info.Settings {
		if _, ok := s[x.Key]; ok {
			return fmt.Errorf("duplicate binary build setting")
		}
		s[x.Key] = x.Value
	}
	parts := strings.Split(target, "-")
	if len(parts) != 2 || s["GOOS"] != parts[0] || s["GOARCH"] != parts[1] || s["CGO_ENABLED"] != "0" || s["vcs"] != "git" || s["vcs.revision"] != sha || s["vcs.modified"] != "true" {
		return fmt.Errorf("binary platform/source provenance mismatch")
	}
	symbol := archiveModule + "/internal.Version="
	assignments := 0
	for _, v := range strings.Fields(s["-ldflags"]) {
		v = strings.TrimPrefix(v, "-X=")
		if strings.HasPrefix(v, symbol) {
			if v != symbol+version {
				return fmt.Errorf("wrong linker version")
			}
			assignments++
		}
	}
	if assignments != 1 {
		return fmt.Errorf("snapshot linker version missing or ambiguous")
	}
	return nil
}

func inspectArchiveBinary(b []byte, target, sha, version string) (*debug.BuildInfo, error) {
	i, e := buildinfo.Read(bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	if e = checkArchiveInfo(i, target, sha, version); e != nil {
		return nil, e
	}
	switch target {
	case "linux-amd64":
		f, e := elf.NewFile(bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
			return nil, fmt.Errorf("wrong ELF target")
		}
	case "darwin-arm64":
		f, e := macho.NewFile(bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if f.Cpu != macho.CpuArm64 || f.Type != macho.TypeExec {
			return nil, fmt.Errorf("wrong Mach-O target")
		}
	default:
		return nil, fmt.Errorf("unsupported target")
	}
	return i, nil
}

type sourceFile struct {
	Mode   string `json:"mode"`
	Blob   string `json:"blob"`
	SHA256 string `json:"sha256"`
}
type sourceState struct {
	Root   string                `json:"root"`
	Commit string                `json:"commit"`
	Tree   string                `json:"tree"`
	Files  map[string]sourceFile `json:"files"`
	// Store exact bytes: RawMessage is normalized by receipt JSON marshaling.
	Manifest []byte `json:"manifest"`
}

// Separate wire shape prevents snapshot/tag receipts from being reused across
// modes. Only deterministic disposable local qualification tags are admitted.
type tagSourceState struct {
	Source *sourceState `json:"source"`
	Tag    string       `json:"tag"`
}

// Wire contract produced by the native post-hook, not a runtime attestation.
// The same-job owner controls these files; no hostile same-user isolation is
// implied. This consumer still binds every fact to current verified bytes.
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

// Reuse the full verifier, including current physical output inventory and
// archive bytes. A stored success report alone cannot attest to present bytes.
// The temporary extraction is owned here, never executed, and removed before
// returning success. This is not an adversarial concurrent-mutation boundary.
func revalidateTagArchiveReport(root, sha, tag string, report *archiveReport, rawReport []byte) (err error) {
	// Resolve placement before creation: TMPDIR inside the source is refused,
	// including directory symlinks that would redirect into the source tree.
	source, e := filepath.EvalSymlinks(root)
	if e != nil {
		return fmt.Errorf("cannot resolve archive recheck source")
	}
	temp, e := filepath.EvalSymlinks(os.TempDir())
	if e != nil {
		return fmt.Errorf("cannot resolve archive recheck temporary directory")
	}
	rel, e := filepath.Rel(source, temp)
	if e != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("archive recheck temporary directory must be outside source")
	}
	owned, e := os.MkdirTemp(temp, "compute-tag-recheck-")
	if e != nil {
		return fmt.Errorf("cannot create owned archive recheck directory")
	}
	defer func() {
		if e := os.RemoveAll(owned); e != nil {
			err = errors.Join(err, fmt.Errorf("tag archive recheck cleanup failed: %w", e))
		}
	}()
	current, e := verifyArchives(root, sha, report.Source, filepath.Join(owned, "extracted"), tag)
	if e != nil {
		return fmt.Errorf("tag archive revalidation failed: %w", e)
	}
	currentJSON, e := json.Marshal(current)
	if e != nil {
		return fmt.Errorf("tag archive recheck report invalid")
	}
	currentValue, e := jsonValue(currentJSON)
	if e != nil {
		return fmt.Errorf("tag archive recheck report invalid")
	}
	// Parse original wire bytes directly. Re-marshaling the decoded report
	// would filter supplied BuildInfo fields and hide unexpected differences.
	previousValue, e := jsonValue(rawReport)
	if e != nil || !reflect.DeepEqual(currentValue, previousValue) {
		return fmt.Errorf("tag archive report changed")
	}
	return nil
}

func bindNativeReceipt(root, sha, tree, tag, reportPath, nativePath string, out io.Writer) error {
	if e := qualificationTagIdentity(root, sha, tree, tag); e != nil {
		return e
	}
	read := func(path string) ([]byte, error) {
		path = filepath.Clean(path)
		return readRegular(filepath.Dir(path), filepath.Base(path), maxMetadata)
	}
	b, e := read(reportPath)
	if e != nil {
		return e
	}
	reportSHA := byteHash(b)
	var report archiveReport
	if e = decodeExact(b, &report); e != nil {
		return e
	}
	if report.Mode != "local-tag" || report.Commit != sha || report.Tree != tree || report.Tag != tag || report.TagVersion != strings.TrimPrefix(tag, "v") || report.Version != "" || report.Compiler != archiveCompiler || report.Source == nil || len(report.Archives) != 2 {
		return fmt.Errorf("tag archive report binding mismatch")
	}
	if e = revalidateTagArchiveReport(root, sha, tag, &report, b); e != nil {
		return e
	}
	manifest, e := verifySource(root, sha, report.TagVersion, report.Source)
	if e != nil {
		return e
	}
	if byteHash(manifest) != report.FinalManifestSHA {
		return fmt.Errorf("tag manifest report mismatch")
	}
	b, e = read(nativePath)
	if e != nil {
		return e
	}
	nativeSHA := byteHash(b)
	var native nativeValidationReceipt
	if e = decodeExact(b, &native); e != nil {
		return e
	}
	if native.Schema != 1 || native.Scope != "runtime-identity-version-declared-iac" || native.Verdict != "pass" || native.Target != "linux-amd64" || native.VerifierSHA != "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8" || !sumSHA.MatchString(native.ArtifactSHA) || native.ManifestSHA != report.FinalManifestSHA {
		return fmt.Errorf("native receipt contract mismatch")
	}
	b, e = readRegular(root, "dist/artifacts.json", maxMetadata)
	if e != nil {
		return e
	}
	if byteHash(b) != report.IndexSHA {
		return fmt.Errorf("artifact index changed since tag verification")
	}
	var index []releaseArtifact
	if e = decodeExact(b, &index); e != nil {
		return e
	}
	count := 0
	for _, a := range index {
		if a.Type == "Binary" && a.Internal == 4 && a.OS == "linux" && a.Arch == "amd64" {
			count++
			if a.Name != archivePlugin || a.Path != native.Artifact {
				return fmt.Errorf("native artifact path/index mismatch")
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("native artifact index is ambiguous")
	}
	data, e := readRegular(root, native.Artifact, maxBinary)
	if e != nil {
		return e
	}
	if byteHash(data) != native.ArtifactSHA {
		return fmt.Errorf("native artifact bytes changed")
	}
	if _, e = inspectArchiveBinary(data, "linux-amd64", sha, report.TagVersion); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, a := range report.Archives {
		if seen[a.Target] || (a.Target != "linux-amd64" && a.Target != "darwin-arm64") || !sumSHA.MatchString(a.BinarySHA) || !sumSHA.MatchString(a.ArchiveSHA) {
			return fmt.Errorf("tag archive target report mismatch")
		}
		seen[a.Target] = true
		if a.Target == "linux-amd64" && a.BinarySHA != native.ArtifactSHA {
			return fmt.Errorf("native artifact/archive digest mismatch")
		}
	}
	if e = qualificationTagIdentity(root, sha, tree, tag); e != nil {
		return e
	}
	// Public validated facts only; no source paths, dependency lists, process
	// output, environment or linker arguments enter the job log.
	return json.NewEncoder(out).Encode(struct {
		Scope             string `json:"scope"`
		Commit            string `json:"commit"`
		Tree              string `json:"tree"`
		Tag               string `json:"tag"`
		Target            string `json:"target"`
		BinarySHA         string `json:"binary_sha256"`
		ManifestSHA       string `json:"manifest_sha256"`
		VerifierSHA       string `json:"verifier_sha256"`
		ArchiveReceiptSHA string `json:"archive_receipt_sha256"`
		NativeReceiptSHA  string `json:"native_receipt_sha256"`
	}{"local-tag-native-identity-version-declared-iac; no publication or full capability parity", sha, tree, tag, native.Target, native.ArtifactSHA, native.ManifestSHA, native.VerifierSHA, reportSHA, nativeSHA})
}

func qualificationTagIdentity(root, sha, tree, tag string) error {
	wanted, e := numericQualificationTag(sha)
	if e != nil || !fullSHA.MatchString(tree) || tag != wanted {
		return fmt.Errorf("qualification tag/source mismatch")
	}
	for _, key := range []string{"GORELEASER_CURRENT_TAG", "GORELEASER_PREVIOUS_TAG"} {
		if _, present := os.LookupEnv(key); present {
			return fmt.Errorf("qualification tag override environment")
		}
	}
	actualTree, e := sourceIdentity(root, sha)
	if e != nil || actualTree != tree {
		return fmt.Errorf("qualification source/tree mismatch")
	}
	ref := "refs/tags/" + tag
	b, e := localGit(root, "for-each-ref", "--format=%(refname)%00%(symref)%00%(objectname)%00%(objecttype)", ref)
	// An exact row requires the fully qualified direct, unsigned/lightweight
	// commit ref. Annotated, symbolic and prefix-matching extra refs fail.
	if e != nil || string(b) != ref+"\x00\x00"+sha+"\x00commit\n" {
		return fmt.Errorf("qualification tag ref mismatch")
	}
	b, e = localGit(root, "tag", "--points-at", sha)
	if e != nil || strings.TrimSpace(string(b)) != tag {
		return fmt.Errorf("ambiguous qualification tag")
	}
	return nil
}

type boundedOutput struct {
	b        bytes.Buffer
	overflow bool
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	n := len(b)
	left := maxMetadata - w.b.Len()
	if left > 0 {
		w.b.Write(b[:min(n, left)])
	}
	if n > left {
		w.overflow = true
	}
	return n, nil
}

func localGit(root string, args ...string) ([]byte, error) {
	c := exec.Command("git", append([]string{"-C", root}, args...)...)
	var out, errout boundedOutput
	c.Stdout = &out
	c.Stderr = &errout
	if e := c.Run(); e != nil || out.overflow || errout.overflow {
		return nil, fmt.Errorf("local Git metadata failed")
	}
	return out.b.Bytes(), nil
}

// Paths and every existing component must remain inside the owned root and be
// nonsymlinks. This is a finite fixture/CI check, not a concurrent race defense.
func regularPath(root, rel string, limit int64) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || filepath.ToSlash(filepath.Clean(rel)) != rel || strings.ContainsAny(rel, "\\\x00\n\r\t") || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("noncanonical path")
	}
	parts := strings.Split(rel, "/")
	p := root
	for n, s := range parts {
		p = filepath.Join(p, s)
		st, e := os.Lstat(p)
		if e != nil {
			return "", e
		}
		if n < len(parts)-1 {
			if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("nonregular parent")
			}
		} else if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > limit {
			return "", fmt.Errorf("nonregular or oversized file")
		}
	}
	return p, nil
}
func readRegular(root, rel string, limit int64) ([]byte, error) {
	p, e := regularPath(root, rel, limit)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file grew beyond limit")
	}
	return b, nil
}

func trackedSource(root string) (map[string]sourceFile, error) {
	b, e := localGit(root, "ls-files", "--stage", "-z")
	if e != nil {
		return nil, e
	}
	files := map[string]sourceFile{}
	for _, row := range bytes.Split(b, []byte{0}) {
		if len(row) == 0 {
			continue
		}
		a := bytes.SplitN(row, []byte{'\t'}, 2)
		if len(a) != 2 {
			return nil, fmt.Errorf("invalid Git index")
		}
		fields := strings.Fields(string(a[0]))
		name := string(a[1])
		if len(fields) != 3 || (fields[0] != "100644" && fields[0] != "100755") || fields[2] != "0" || !fullSHA.MatchString(fields[1]) || len(files) >= 256 {
			return nil, fmt.Errorf("unsupported index entry")
		}
		data, e := readRegular(root, name, maxSourceFile)
		if e != nil {
			return nil, e
		}
		st, e := os.Lstat(filepath.Join(root, name))
		if e != nil {
			return nil, e
		}
		mode := "100644"
		if st.Mode()&0o111 != 0 {
			mode = "100755"
		}
		if mode != fields[0] {
			return nil, fmt.Errorf("source mode mismatch")
		}
		files[name] = sourceFile{Mode: mode, Blob: fields[1], SHA256: byteHash(data)}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("empty source index")
	}
	return files, nil
}

func sourceIdentity(root, expected string) (string, error) {
	if !fullSHA.MatchString(expected) {
		return "", fmt.Errorf("invalid expected source SHA")
	}
	b, e := localGit(root, "rev-parse", "HEAD", "HEAD^{tree}")
	if e != nil {
		return "", e
	}
	rows := strings.Fields(string(b))
	if len(rows) != 2 || rows[0] != expected || !fullSHA.MatchString(rows[1]) {
		return "", fmt.Errorf("source commit mismatch")
	}
	return rows[1], nil
}

func sourceStatus(root string, after bool) error {
	b, e := localGit(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored")
	if e != nil {
		return e
	}
	for _, row := range bytes.Split(b, []byte{0}) {
		if len(row) == 0 {
			continue
		}
		s := string(row)
		if after && (s == " M plugin.json" || strings.HasPrefix(s, "!! dist/")) {
			continue
		}
		return unexpectedWorktreeChange(row, after)
	}
	return nil
}

// Status diagnostics disclose only fixed public contract paths. Unknown names
// (including control characters) are fingerprinted, never copied into logs.
// This does not change which status entries are admitted above.
func unexpectedWorktreeChange(row []byte, after bool) error {
	phase := "pre-build"
	if after {
		phase = "post-build"
	}
	category, xy := "malformed", "none"
	path := row
	if len(row) >= 3 && row[2] == ' ' {
		xy = fmt.Sprintf("%x", row[:2])
		path = row[3:]
		category = map[string]string{" M": "worktree-modified", "M ": "index-modified", "MM": "index-and-worktree-modified", "??": "untracked", "!!": "ignored", "A ": "index-added", " D": "worktree-deleted", "D ": "index-deleted", "R ": "index-renamed", " R": "worktree-renamed", "C ": "index-copied", "UU": "unmerged", "AA": "unmerged", "DD": "unmerged", " T": "worktree-type-changed", "T ": "index-type-changed"}[string(row[:2])]
		if category == "" {
			category = "other"
		}
	}
	label, class := "redacted", "other"
	switch string(path) {
	case "plugin.json", "go.mod", "go.sum", ".gitignore", ".goreleaser.yaml", "dist", "dist/", "bin", "bin/", archivePlugin,
		"dist/config.yaml", "dist/metadata.json", "dist/artifacts.json", "dist/checksums.txt",
		"scripts/check-release-archives.go", "scripts/check-release-archives_test.go", "scripts/check-build-toolchain.go", ".github/workflows/archive-qualification.yml":
		label = string(path)
		class = "public-contract"
	default:
		for _, prefix := range []string{"dist/", "bin/", "scripts/", "internal/", "docs/", ".github/"} {
			if bytes.HasPrefix(path, []byte(prefix)) {
				class = strings.TrimSuffix(prefix, "/") + "-child"
				break
			}
		}
	}
	return fmt.Errorf("unexpected source/worktree change: phase=%s category=%s xy_hex=%s path=%s path_class=%s path_bytes=%d path_sha256=%s", phase, category, xy, label, class, len(path), byteHash(path))
}

func captureSource(root, sha string) (*sourceState, error) {
	tree, e := sourceIdentity(root, sha)
	if e != nil {
		return nil, e
	}
	if e = sourceStatus(root, false); e != nil {
		return nil, e
	}
	files, e := trackedSource(root)
	if e != nil {
		return nil, e
	}
	for name, f := range files {
		b, e := readRegular(root, name, maxSourceFile)
		if e != nil {
			return nil, e
		}
		gitBlob := fmt.Sprintf("%x", sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(b))), b...)))
		if gitBlob != f.Blob {
			return nil, fmt.Errorf("raw tracked bytes differ from Git source")
		}
	}
	manifest, e := readRegular(root, "plugin.json", maxManifest)
	if e != nil {
		return nil, e
	}
	if _, e = jsonValue(manifest); e != nil {
		return nil, e
	}
	return &sourceState{Root: root, Commit: sha, Tree: tree, Files: files, Manifest: manifest}, nil
}

func verifySource(root, sha, version string, before *sourceState) ([]byte, error) {
	tree, e := sourceIdentity(root, sha)
	if e != nil {
		return nil, e
	}
	if before.Root != root || before.Commit != sha || before.Tree != tree || len(before.Files) == 0 {
		return nil, fmt.Errorf("source receipt mismatch")
	}
	if e = sourceStatus(root, true); e != nil {
		return nil, e
	}
	files, e := trackedSource(root)
	if e != nil {
		return nil, e
	}
	if len(files) != len(before.Files) {
		return nil, fmt.Errorf("source file set changed")
	}
	for name, old := range before.Files {
		now, ok := files[name]
		if !ok || old.Mode != now.Mode || old.Blob != now.Blob || (name != "plugin.json" && old.SHA256 != now.SHA256) {
			return nil, fmt.Errorf("source/index/mode changed beyond manifest version")
		}
	}
	manifest, e := readRegular(root, "plugin.json", maxManifest)
	if e != nil {
		return nil, e
	}
	if before.Files["plugin.json"].SHA256 != byteHash(before.Manifest) {
		return nil, fmt.Errorf("original manifest receipt mismatch")
	}
	if e = sameManifest(before.Manifest, manifest, version); e != nil {
		return nil, e
	}
	return manifest, nil
}

type releaseMetadata struct {
	Project  string `json:"project_name"`
	Tag      string `json:"tag"`
	Previous string `json:"previous_tag"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Runtime  struct {
		OS   string `json:"goos"`
		Arch string `json:"goarch"`
	} `json:"runtime"`
}
type releaseArtifact struct {
	Name     string          `json:"name"`
	Path     string          `json:"path"`
	OS       string          `json:"goos"`
	Arch     string          `json:"goarch"`
	AMD64    string          `json:"goamd64"`
	I386     string          `json:"go386"`
	ARM      string          `json:"goarm"`
	ARM64    string          `json:"goarm64"`
	MIPS     string          `json:"gomips"`
	PPC      string          `json:"goppc64"`
	RISCV    string          `json:"goriscv64"`
	Target   string          `json:"target"`
	Internal int             `json:"internal_type"`
	Type     string          `json:"type"`
	Extra    json.RawMessage `json:"extra"`
}
type verifiedArchive struct {
	Target      string           `json:"target"`
	ArchiveSHA  string           `json:"archive_sha256"`
	BinarySHA   string           `json:"binary_sha256"`
	BinaryBytes int              `json:"binary_bytes"`
	BuildInfo   *debug.BuildInfo `json:"build_info"`
}

// Receipt consumers need the validated compiler/target/source facts, not a
// dependency catalog, replacement paths, arbitrary settings or linker values.
// The existing compiler checker still performs its independent full inspection.
func (a verifiedArchive) MarshalJSON() ([]byte, error) {
	type publicArchive verifiedArchive
	if in := a.BuildInfo; in != nil {
		if in.GoVersion != archiveCompiler || in.Path != archiveModule+"/cmd/"+archivePlugin || in.Main.Path != archiveModule {
			return nil, fmt.Errorf("unvalidated archive metadata cannot be reported")
		}
		public := &debug.BuildInfo{GoVersion: in.GoVersion, Path: in.Path, Main: debug.Module{Path: in.Main.Path}}
		for _, s := range in.Settings {
			switch s.Key {
			case "GOOS", "GOARCH", "CGO_ENABLED", "vcs", "vcs.revision", "vcs.modified":
				public.Settings = append(public.Settings, s)
			}
		}
		a.BuildInfo = public
	}
	return json.Marshal(publicArchive(a))
}

type archiveReport struct {
	Scope              string            `json:"scope"`
	Compiler           string            `json:"compiler"`
	Commit             string            `json:"commit"`
	Tree               string            `json:"tree"`
	Version            string            `json:"snapshot_version,omitempty"`
	TagVersion         string            `json:"tag_version,omitempty"`
	Tag                string            `json:"tag,omitempty"`
	Mode               string            `json:"verification_mode,omitempty"`
	Source             *sourceState      `json:"original_source"`
	FinalManifestSHA   string            `json:"final_manifest_sha256"`
	Archives           []verifiedArchive `json:"archives"`
	EffectiveConfig    string            `json:"effective_config"`
	EffectiveConfigSHA string            `json:"effective_config_sha256"`
	MetadataSHA        string            `json:"metadata_sha256"`
	IndexSHA           string            `json:"artifact_index_sha256"`
	ChecksumsSHA       string            `json:"checksums_sha256"`
}

// Check physical output independently of artifacts.json. The current snapshot
// produces exactly its six indexed files plus config.yaml and artifacts.json.
// Unknown outputs, including unindexed archives, fail instead of disappearing
// from evidence. Parent directories are inferred only from admitted file paths.
func verifyDistInventory(root string, artifacts []releaseArtifact) error {
	allowed := map[string]bool{"dist/config.yaml": true, "dist/artifacts.json": true}
	dirs := map[string]bool{"dist": true}
	for _, a := range artifacts {
		allowed[a.Path] = true
		for d := filepath.ToSlash(filepath.Dir(a.Path)); d != "."; d = filepath.ToSlash(filepath.Dir(d)) {
			dirs[d] = true
		}
	}
	seen := map[string]bool{}
	entries := 0
	var total int64
	err := filepath.WalkDir(filepath.Join(root, "dist"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > 128 {
			return fmt.Errorf("dist entry limit")
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if !dirs[rel] {
				return fmt.Errorf("unindexed dist directory")
			}
			return nil
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || !allowed[rel] {
			return fmt.Errorf("unindexed or nonregular dist output")
		}
		total += st.Size()
		if total > 512<<20 {
			return fmt.Errorf("dist byte limit")
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(allowed) {
		return fmt.Errorf("missing physical dist output")
	}
	return nil
}

func verifySnapshot(root, sha string, before *sourceState, extract string) (*archiveReport, error) {
	return verifyArchives(root, sha, before, extract, "")
}

func verifyArchives(root, sha string, before *sourceState, extract, tag string) (*archiveReport, error) {
	if before == nil {
		return nil, fmt.Errorf("source receipt missing")
	}
	if tag != "" {
		if e := qualificationTagIdentity(root, sha, before.Tree, tag); e != nil {
			return nil, e
		}
	}
	b, e := readRegular(root, "dist/metadata.json", maxMetadata)
	if e != nil {
		return nil, e
	}
	metadataSHA := byteHash(b)
	var meta releaseMetadata
	if e = decodeExact(b, &meta); e != nil {
		return nil, e
	}
	if meta.Project != archivePlugin || meta.Commit != sha || meta.Runtime.OS != runtime.GOOS || meta.Runtime.Arch != runtime.GOARCH {
		return nil, fmt.Errorf("release metadata source/host mismatch")
	}
	if tag == "" {
		if e = checkSnapshotVersion(meta.Version, sha); e != nil {
			return nil, e
		}
	} else if meta.Tag != tag || meta.Version != strings.TrimPrefix(tag, "v") {
		return nil, fmt.Errorf("tag metadata version/source mismatch")
	}
	manifest, e := verifySource(root, sha, meta.Version, before)
	if e != nil {
		return nil, e
	}
	b, e = readRegular(root, "dist/checksums.txt", 4096)
	if e != nil {
		return nil, e
	}
	sums, e := parseChecksums(b)
	if e != nil {
		return nil, e
	}
	checksumsSHA := byteHash(b)
	b, e = readRegular(root, "dist/artifacts.json", maxMetadata)
	if e != nil {
		return nil, e
	}
	indexSHA := byteHash(b)
	var artifacts []releaseArtifact
	if e = decodeExact(b, &artifacts); e != nil {
		return nil, e
	}
	bins := map[string]releaseArtifact{}
	archives := map[string]releaseArtifact{}
	seen := map[string]bool{}
	metadataCount, checksumCount := 0, 0
	for _, a := range artifacts {
		// The pinned v2.20.3 engine emits both the enum and its human-readable
		// type. Metadata is 36 after WingetLocale was added; do not accept the
		// old v2.16.0 value or conflicting classifications.
		kind := map[string]int{"Binary": 4, "Archive": 1, "Checksum": 12, "Metadata": 36}[a.Type]
		if kind == 0 || a.Internal != kind {
			return nil, fmt.Errorf("artifact wire type mismatch")
		}
		if seen[a.Path] || !strings.HasPrefix(a.Path, "dist/") {
			return nil, fmt.Errorf("duplicate/outside artifact path")
		}
		seen[a.Path] = true
		if _, e = regularPath(root, a.Path, maxBinary); e != nil {
			return nil, e
		}
		target := a.OS + "-" + a.Arch
		switch a.Type {
		case "Binary":
			if a.Name != archivePlugin || (target != targets[0] && target != targets[1]) || bins[target].Path != "" {
				return nil, fmt.Errorf("unexpected binary artifact")
			}
			bins[target] = a
		case "Archive":
			if a.Name != archiveName(target) || a.Path != "dist/"+a.Name || (target != targets[0] && target != targets[1]) || archives[target].Path != "" {
				return nil, fmt.Errorf("unexpected archive artifact")
			}
			archives[target] = a
		case "Checksum":
			if a.Name != "checksums.txt" || a.Path != "dist/checksums.txt" {
				return nil, fmt.Errorf("unexpected checksum artifact")
			}
			checksumCount++
		case "Metadata":
			if a.Name != "metadata.json" || a.Path != "dist/metadata.json" {
				return nil, fmt.Errorf("unexpected metadata artifact")
			}
			metadataCount++
		default:
			return nil, fmt.Errorf("unexpected artifact type")
		}
	}
	if len(bins) != 2 || len(archives) != 2 || metadataCount != 1 || checksumCount != 1 {
		return nil, fmt.Errorf("incomplete artifact inventory")
	}
	if e = verifyDistInventory(root, artifacts); e != nil {
		return nil, e
	}
	effective, e := readRegular(root, "dist/config.yaml", maxManifest)
	if e != nil {
		return nil, e
	}
	if len(effective) == 0 || !utf8.Valid(effective) || bytes.IndexByte(effective, 0) >= 0 {
		return nil, fmt.Errorf("invalid effective configuration text")
	}
	if !sumSHA.MatchString(before.Files[".goreleaser.yaml"].SHA256) {
		return nil, fmt.Errorf("original configuration not bound to source")
	}
	if e = os.Mkdir(extract, 0o700); e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(extract)
		}
	}()
	report := &archiveReport{Scope: "snapshot archives only; no binary execution or official release acceptance", Compiler: runtime.Version(), Commit: sha, Tree: before.Tree, Version: meta.Version, Source: before, FinalManifestSHA: byteHash(manifest)}
	if tag != "" {
		report.Scope = "local synthetic tag-mode archives only; no binary execution or official release acceptance"
		report.Version, report.TagVersion, report.Tag, report.Mode = "", meta.Version, tag, "local-tag"
	}
	report.EffectiveConfig = string(effective)
	report.EffectiveConfigSHA = byteHash(effective)
	report.MetadataSHA = metadataSHA
	report.IndexSHA = indexSHA
	report.ChecksumsSHA = checksumsSHA
	for _, target := range targets {
		data, e := readRegular(root, archives[target].Path, maxBinary)
		if e != nil {
			return nil, e
		}
		digest := byteHash(data)
		if digest != sums[archiveName(target)] {
			return nil, fmt.Errorf("archive checksum mismatch")
		}
		files, e := readArchive(bytes.NewReader(data), 256<<20)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(files["plugin.json"], manifest) {
			return nil, fmt.Errorf("archived manifest mismatch")
		}
		original, e := readRegular(root, bins[target].Path, maxBinary)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(original, files[archivePlugin]) {
			return nil, fmt.Errorf("archive binary differs from built bytes")
		}
		info, e := inspectArchiveBinary(files[archivePlugin], target, sha, meta.Version)
		if e != nil {
			return nil, e
		}
		dir := filepath.Join(extract, target)
		if e = os.Mkdir(dir, 0o700); e != nil {
			return nil, e
		}
		if e = writeExclusive(filepath.Join(dir, archivePlugin), files[archivePlugin]); e != nil {
			return nil, e
		}
		report.Archives = append(report.Archives, verifiedArchive{Target: target, ArchiveSHA: digest, BinarySHA: byteHash(files[archivePlugin]), BinaryBytes: len(files[archivePlugin]), BuildInfo: info})
	}
	if _, e = verifySource(root, sha, meta.Version, before); e != nil {
		return nil, e
	}
	if tag != "" {
		// Keep this inside the owned extraction cleanup boundary: no success
		// receipt or leftover output if the source/tag binding has changed.
		if e = qualificationTagIdentity(root, sha, before.Tree, tag); e != nil {
			return nil, e
		}
	}
	success = true
	return report, nil
}

func writeExclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}

func runArchiveCheck(args []string, out io.Writer) error {
	if runtime.Version() != archiveCompiler || os.Getenv("GOTOOLCHAIN") != "local" {
		return fmt.Errorf("archive verifier requires %s and GOTOOLCHAIN=local", archiveCompiler)
	}
	if len(args) < 3 || !fullSHA.MatchString(args[1]) {
		return fmt.Errorf("usage: check-release-archives capture SHA STATE | verify SHA STATE EXTRACT | capture-tag SHA TREE TAG STATE | verify-tag SHA TREE TAG STATE EXTRACT | bind-native SHA TREE TAG REPORT NATIVE")
	}
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	switch args[0] {
	case "bind-native":
		if len(args) != 6 {
			return fmt.Errorf("bind-native requires SHA TREE TAG REPORT NATIVE")
		}
		return bindNativeReceipt(root, args[1], args[2], args[3], args[4], args[5], out)
	case "capture-tag":
		if len(args) != 5 {
			return fmt.Errorf("capture-tag requires SHA TREE TAG STATE")
		}
		if e = qualificationTagIdentity(root, args[1], args[2], args[3]); e != nil {
			return e
		}
		state, e := captureSource(root, args[1])
		if e != nil {
			return e
		}
		if state.Tree != args[2] {
			return fmt.Errorf("qualification source/tree mismatch")
		}
		if e = qualificationTagIdentity(root, args[1], args[2], args[3]); e != nil {
			return e
		}
		b, e := json.Marshal(tagSourceState{Source: state, Tag: args[3]})
		if e != nil {
			return e
		}
		if len(b) > maxMetadata {
			return fmt.Errorf("source receipt limit")
		}
		return writeExclusive(args[4], b)
	case "verify-tag":
		if len(args) != 6 {
			return fmt.Errorf("verify-tag requires SHA TREE TAG STATE EXTRACT")
		}
		wanted, tagErr := numericQualificationTag(args[1])
		if tagErr != nil || !fullSHA.MatchString(args[2]) || args[3] != wanted {
			return fmt.Errorf("qualification tag/source mismatch")
		}
		statePath := filepath.Clean(args[4])
		b, e := readRegular(filepath.Dir(statePath), filepath.Base(statePath), maxMetadata)
		if e != nil {
			return e
		}
		var state tagSourceState
		if e = decodeExact(b, &state); e != nil {
			return e
		}
		if state.Source == nil || state.Tag != args[3] || state.Source.Commit != args[1] || state.Source.Tree != args[2] {
			return fmt.Errorf("tag source receipt mismatch")
		}
		report, e := verifyArchives(root, args[1], state.Source, args[5], args[3])
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(report)
	case "capture":
		if len(args) != 3 {
			return fmt.Errorf("capture arguments")
		}
		state, e := captureSource(root, args[1])
		if e != nil {
			return e
		}
		b, e := json.Marshal(state)
		if e != nil {
			return e
		}
		if len(b) > maxMetadata {
			return fmt.Errorf("source receipt limit")
		}
		return writeExclusive(args[2], b)
	case "verify":
		if len(args) != 4 {
			return fmt.Errorf("verify arguments")
		}
		statePath := filepath.Clean(args[2])
		dir := filepath.Dir(statePath)
		b, e := readRegular(dir, filepath.Base(statePath), maxMetadata)
		if e != nil {
			return e
		}
		var state sourceState
		if e = decodeExact(b, &state); e != nil {
			return e
		}
		report, e := verifySnapshot(root, args[1], &state, args[3])
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(report)
	default:
		return fmt.Errorf("unknown archive verifier mode")
	}
}

func main() {
	if e := runArchiveCheck(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "archive qualification:", e)
		os.Exit(1)
	}
}

// numericQualificationTag is only for unsigned local qualification refs.
// Encode all160 SHA bits as56/52/52-bit canonical decimal components: the
// released wfctl v0.78.2 parser accepts three signed64-bit numeric components,
// but refuses prerelease syntax. Keep these large versions out of releases.
func numericQualificationTag(sha string) (string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) || sha == "0000000000000000000000000000000000000000" {
		return "", fmt.Errorf("invalid qualification source")
	}
	chunks := []string{sha[:14], sha[14:27], sha[27:]}
	var values [3]uint64
	for i, chunk := range chunks {
		n, e := strconv.ParseUint(chunk, 16, 64)
		if e != nil {
			return "", fmt.Errorf("invalid qualification source")
		}
		values[i] = n
	}
	return fmt.Sprintf("v%d.%d.%d", values[0], values[1], values[2]), nil
}
