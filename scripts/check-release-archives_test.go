//go:build ignore

// Run with go test check-release-archives.go check-release-archives_test.go.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func workflowContract(b string) bool {
	for _, required := range []string{
		"  pull_request:\n", "    branches: [main, master]", "  contents: read\n",
		"github.event.pull_request.head.repo.full_name == github.repository",
		"persist-credentials: false", "cache: false", "go-version: '1.27.4'",
		"actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
		"actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
		"goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de",
		"version: v2.16.0", "install-only: true", "GOTOOLCHAIN: local",
		"check --config=.goreleaser.yaml", "release --config=.goreleaser.yaml --snapshot --clean",
		"--skip=publish,sign,notarize,sbom,docker,ko --parallelism=1 --timeout=10m",
		"GOPROXY=off", "GOVCS='*:off'", "GOSUMDB=off", "env -i",
		"check-release-archives.go capture", "check-release-archives.go verify",
		"extracted/linux-amd64/workflow-plugin-compute", "extracted/darwin-arm64/workflow-plugin-compute",
		"upcoming gate", "floating", "~> v2",
	} {
		if !strings.Contains(b, required) {
			return false
		}
	}
	for _, forbidden := range []string{"contents: write", "id-token:", "packages:", "pull_request_target:", "workflow_dispatch:", "workflow_run:", "repository_dispatch:", "  push:", "upload-artifact", "actions/cache", "--skip=before", "--skip=post-hooks"} {
		if strings.Contains(b, forbidden) {
			return false
		}
	}
	if strings.Count(b, "secrets.RELEASES_TOKEN") != 1 {
		return false
	}
	a := strings.Index(b, "      - name: Acquire pinned dependencies")
	z := strings.Index(b, "      - name: Qualify archives without credentials")
	if a < 0 || z <= a {
		return false
	}
	acquire := b[a:z]
	for _, forbidden := range []string{"go run", "go test", "go generate", "goreleaser ", "scripts/", "wfctl ", "bash -c"} {
		if strings.Contains(acquire, forbidden) {
			return false
		}
	}
	return strings.Contains(acquire, "CGO_ENABLED=0") && strings.Contains(acquire, "GOPACKAGESDRIVER=off") && strings.Contains(acquire, "mod tidy -diff")
}

func TestArchiveWorkflow(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/archive-qualification.yml")
	if err != nil {
		t.Fatalf("publication-free archive workflow is missing: %v", err)
	}
	if !workflowContract(string(b)) {
		t.Fatal("archive workflow does not enforce the reviewed contract")
	}
}

func TestArchiveWorkflowRefusals(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/archive-qualification.yml")
	if err != nil {
		t.Fatalf("publication-free archive workflow is missing: %v", err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"write", "contents: read", "contents: write"},
		{"implicit-config", "check --config=.goreleaser.yaml", "check"},
		{"publish", "--skip=publish,sign", "--skip=sign"},
		{"old-compiler", "go-version: '1.27.4'", "go-version: '1.26.11'"},
		{"mutable-action", "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16", "actions/setup-go@v6"},
		{"code-during-acquisition", "mod tidy -diff", "run ./script.go"},
		{"unrestricted-vcs", "GOVCS='*:off'", "GOVCS='*:all'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(b), tc.from) {
				t.Fatal("inverse input is missing")
			}
			if workflowContract(strings.ReplaceAll(string(b), tc.from, tc.to)) {
				t.Fatal("unsafe workflow accepted")
			}
		})
	}
}

func fixtureArchive(t *testing.T, names []string, kinds []byte, tail []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for i, n := range names {
		body := []byte("harmless synthetic bytes")
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if len(kinds) > i {
			h.Typeflag = kinds[i]
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
			h.Linkname = "inert-owned-target"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw.Write(tail)
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestArchiveStream(t *testing.T) {
	good := fixtureArchive(t, []string{"workflow-plugin-compute", "plugin.json"}, nil, make([]byte, 512))
	if files, err := readArchive(bytes.NewReader(good), 4096); err != nil || len(files) != 2 {
		t.Fatalf("valid real gzip/tar refused: %v", err)
	}
	badCRC := append([]byte(nil), good...)
	badCRC[len(badCRC)-8] ^= 1
	for _, tc := range []struct {
		name  string
		data  []byte
		limit int64
	}{
		{"missing", fixtureArchive(t, []string{"plugin.json"}, nil, nil), 4096},
		{"duplicate", fixtureArchive(t, []string{"workflow-plugin-compute", "plugin.json", "plugin.json"}, nil, nil), 8192},
		{"extra", fixtureArchive(t, []string{"workflow-plugin-compute", "plugin.json", "extra"}, nil, nil), 8192},
		{"noncanonical", fixtureArchive(t, []string{"./workflow-plugin-compute", "plugin.json"}, nil, nil), 4096},
		{"link", fixtureArchive(t, []string{"workflow-plugin-compute", "plugin.json"}, []byte{tar.TypeSymlink}, nil), 4096},
		{"crc", badCRC, 4096},
		{"trailer-truncated", good[:len(good)-4], 4096},
		{"header-truncated", good[:4], 4096},
		{"second-member", append(append([]byte(nil), good...), good...), 8192},
		{"raw-trailing", append(append([]byte(nil), good...), 1), 8192},
		{"decoded-trailing", fixtureArchive(t, []string{"workflow-plugin-compute", "plugin.json"}, nil, []byte{1}), 4096},
		{"bounded", good, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readArchive(bytes.NewReader(tc.data), tc.limit); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}

func TestArchiveExtensions(t *testing.T) {
	makeTar := func(format tar.Format, extra map[string]string) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		for _, name := range []string{archivePlugin, "plugin.json"} {
			b := []byte("inert bytes")
			h := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: format, PAXRecords: extra}
			if format == tar.FormatPAX {
				h.ModTime = time.Unix(1234567890, 123000000)
			}
			if e := tw.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			if _, e := tw.Write(b); e != nil {
				t.Fatal(e)
			}
		}
		if e := tw.Close(); e != nil {
			t.Fatal(e)
		}
		if e := gz.Close(); e != nil {
			t.Fatal(e)
		}
		return out.Bytes()
	}
	if _, e := readArchive(bytes.NewReader(makeTar(tar.FormatPAX, nil)), 8192); e != nil {
		t.Fatal("safe timestamp PAX metadata refused:", e)
	}
	for _, tc := range []struct {
		name   string
		format tar.Format
		extra  map[string]string
	}{
		{"unknown-pax", tar.FormatPAX, map[string]string{"comment": "inert"}},
		{"gnu", tar.FormatGNU, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := readArchive(bytes.NewReader(makeTar(tc.format, tc.extra)), 8192); e == nil {
				t.Fatal("unreviewed tar extension accepted")
			}
		})
	}
}

func TestChecksumBinding(t *testing.T) {
	line := strings.Repeat("a", 64) + "  workflow-plugin-compute-linux-amd64.tar.gz\n"
	other := strings.Repeat("b", 64) + "  workflow-plugin-compute-darwin-arm64.tar.gz\n"
	if rows, err := parseChecksums([]byte(line + other)); err != nil || len(rows) != 2 {
		t.Fatalf("valid checksum set refused: %v", err)
	}
	for _, tc := range []struct{ name, data string }{
		{"missing", line}, {"duplicate", line + line}, {"extra", line + other + line},
		{"uppercase", strings.ToUpper(line) + other}, {"path", strings.ReplaceAll(line, "  workflow", "  dist/workflow") + other},
		{"digest", strings.Replace(line, strings.Repeat("a", 64), "short", 1) + other},
		{"separator", strings.Replace(line, "  ", " ", 1) + other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseChecksums([]byte(tc.data)); err == nil {
				t.Fatal("invalid checksums accepted")
			}
		})
	}
}

func TestManifestBinding(t *testing.T) {
	old := []byte(`{"name":"workflow-plugin-compute","version":"0.1.10","capabilities":{"cliCommands":["compute"]}}`)
	version := "0.1.15-SNAPSHOT-abcdef0"
	good := []byte(strings.Replace(string(old), "0.1.10", version, 1))
	if err := sameManifest(old, good, version); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, data string }{
		{"version", string(old)},
		{"name", strings.Replace(string(good), "workflow-plugin-compute", "other", 1)},
		{"capability", strings.Replace(string(good), `["compute"]`, `[]`, 1)},
		{"duplicate", strings.Replace(string(good), `"name":`, `"version":"extra","name":`, 1)},
		{"nested-duplicate", strings.Replace(string(good), `"cliCommands":`, `"cliCommands":[],"cliCommands":`, 1)},
		{"trailing", string(good) + ` {}`},
		{"unknown-added", strings.Replace(string(good), `"name":`, `"extra":true,"name":`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := sameManifest(old, []byte(tc.data), version); err == nil {
				t.Fatal("manifest drift accepted")
			}
		})
	}
}

func fixtureInfo() *debug.BuildInfo {
	return &debug.BuildInfo{GoVersion: "go1.27.4", Path: "github.com/GoCodeAlone/workflow-plugin-compute/cmd/workflow-plugin-compute", Main: debug.Module{Path: "github.com/GoCodeAlone/workflow-plugin-compute"}, Settings: []debug.BuildSetting{
		{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "CGO_ENABLED", Value: "0"},
		{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.modified", Value: "true"},
		{Key: "-ldflags", Value: "-s -w -X github.com/GoCodeAlone/workflow-plugin-compute/internal.Version=0.1.15-SNAPSHOT-aaaaaaa"},
	}}
}

func TestBuildMetadataBinding(t *testing.T) {
	sha := strings.Repeat("a", 40)
	version := "0.1.15-SNAPSHOT-aaaaaaa"
	if err := checkArchiveInfo(fixtureInfo(), "linux-amd64", sha, version); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*debug.BuildInfo)
	}{
		{"compiler", func(i *debug.BuildInfo) { i.GoVersion = "go1.26.11" }},
		{"command", func(i *debug.BuildInfo) { i.Path = "example.invalid/other" }},
		{"module", func(i *debug.BuildInfo) { i.Main.Path = "example.invalid/other" }},
		{"missing-vcs", func(i *debug.BuildInfo) { i.Settings = i.Settings[:3] }},
		{"clean", func(i *debug.BuildInfo) { i.Settings[5].Value = "false" }},
		{"revision", func(i *debug.BuildInfo) { i.Settings[4].Value = strings.Repeat("b", 40) }},
		{"arch", func(i *debug.BuildInfo) { i.Settings[1].Value = "arm64" }},
		{"cgo", func(i *debug.BuildInfo) { i.Settings[2].Value = "1" }},
		{"linker-version", func(i *debug.BuildInfo) { i.Settings[6].Value = "-s -w" }},
		{"duplicate-setting", func(i *debug.BuildInfo) { i.Settings = append(i.Settings, i.Settings[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := fixtureInfo()
			tc.edit(i)
			if err := checkArchiveInfo(i, "linux-amd64", sha, version); err == nil {
				t.Fatal("wrong binary metadata accepted")
			}
		})
	}
}

func TestSnapshotVersionBinding(t *testing.T) {
	sha := strings.Repeat("a", 40)
	if err := checkSnapshotVersion("0.1.15-SNAPSHOT-aaaaaaa", sha); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"0.1.15", "0.1.15-SNAPSHOT-bbbbbbb", "0.1.15-SNAPSHOT-a", "other-SNAPSHOT-aaaaaaa", "0.1.15-SNAPSHOT-AAAAAAA"} {
		if checkSnapshotVersion(v, sha) == nil {
			t.Fatalf("wrong snapshot version accepted: %q", v)
		}
	}
}

// These helpers create inert bytes only; they never execute an archived binary.
func checksumBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

func TestArchiveInputAnchors(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/archive-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{".goreleaser.yaml", "scripts/check-build-toolchain.go", "go.mod", "go.sum", "scripts/check-release-archives.go", "scripts/check-release-archives_test.go"} {
		data, e := os.ReadFile(filepath.Join("..", n))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Count(string(b), checksumBytes(data)+"  "+n) != 2 {
			t.Errorf("both pre-acquisition and packaging anchors must match %s", n)
		}
	}
}

func fixtureGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", root, "-c", "core.hooksPath=/dev/null", "-c", "user.name=ArchiveFixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z")
	var out, errout boundedOutput
	c.Stdout = &out
	c.Stderr = &errout
	if e := c.Run(); e != nil || out.overflow || errout.overflow {
		t.Fatalf("owned fixture Git failed: %v %s", e, errout.b.String())
	}
	return strings.TrimSpace(out.b.String())
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, data, 0o600); e != nil {
		t.Fatal(e)
	}
}

func newSourceFixture(t *testing.T) (string, string, *sourceState) {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		".goreleaser.yaml":                    "version: 2\nproject_name: workflow-plugin-compute\n",
		".gitignore":                          "dist/\n",
		"plugin.json":                         `{"name":"workflow-plugin-compute","version":"0.1.10","capabilities":{"cliCommands":["compute"]}}`,
		"go.mod":                              "module github.com/GoCodeAlone/workflow-plugin-compute\n\ngo 1.26.4\n",
		"internal/version.go":                 "package internal\nvar Version = \"dev\"\n",
		"cmd/workflow-plugin-compute/main.go": "package main\nimport \"github.com/GoCodeAlone/workflow-plugin-compute/internal\"\nfunc main(){println(internal.Version)}\n",
	} {
		writeFixture(t, filepath.Join(root, name), []byte(body))
	}
	fixtureGit(t, root, "init", "-q", "-b", "main")
	fixtureGit(t, root, "add", ".")
	fixtureGit(t, root, "commit", "-qm", "inert fixture")
	sha := fixtureGit(t, root, "rev-parse", "HEAD")
	before, e := captureSource(root, sha)
	if e != nil {
		t.Fatal(e)
	}
	return root, sha, before
}

func TestSourceBinding(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	version := "0.1.15-SNAPSHOT-" + sha[:7]
	updated := []byte(strings.Replace(string(before.Manifest), "0.1.10", version, 1))
	writeFixture(t, filepath.Join(root, "plugin.json"), updated)
	if _, e := verifySource(root, sha, version, before); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name            string
		change, restore func()
	}{
		{"wrong-source", func() { before.Commit = strings.Repeat("b", 40) }, func() { before.Commit = sha }},
		{"source-bytes", func() {
			writeFixture(t, filepath.Join(root, "internal/version.go"), []byte("package internal\nvar Version=\"changed\"\n"))
		}, func() {
			writeFixture(t, filepath.Join(root, "internal/version.go"), []byte("package internal\nvar Version = \"dev\"\n"))
		}},
		{"hidden-source-bytes", func() {
			fixtureGit(t, root, "update-index", "--assume-unchanged", "internal/version.go")
			writeFixture(t, filepath.Join(root, "internal/version.go"), []byte("package internal\nvar Version=\"hidden\"\n"))
		}, func() {
			writeFixture(t, filepath.Join(root, "internal/version.go"), []byte("package internal\nvar Version = \"dev\"\n"))
			fixtureGit(t, root, "update-index", "--no-assume-unchanged", "internal/version.go")
		}},
		{"extra-file", func() { writeFixture(t, filepath.Join(root, "extra"), []byte("inert")) }, func() {
			if e := os.Remove(filepath.Join(root, "extra")); e != nil {
				t.Fatal(e)
			}
		}},
		{"index", func() { fixtureGit(t, root, "add", "plugin.json") }, func() { fixtureGit(t, root, "reset", "-q", "HEAD", "--", "plugin.json") }},
		{"mode", func() {
			if e := os.Chmod(filepath.Join(root, "internal/version.go"), 0o700); e != nil {
				t.Fatal(e)
			}
		}, func() {
			if e := os.Chmod(filepath.Join(root, "internal/version.go"), 0o600); e != nil {
				t.Fatal(e)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			defer tc.restore()
			if _, e := verifySource(root, sha, version, before); e == nil {
				t.Fatal("source drift accepted")
			}
		})
	}
	if _, e := verifySource(root, sha, version, before); e != nil {
		t.Fatal(e)
	}
	if _, e := captureSource(root, sha); e == nil {
		t.Fatal("dirty initial source accepted")
	}
	if e := writeExclusive(filepath.Join(root, "exclusive"), []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := writeExclusive(filepath.Join(root, "exclusive"), []byte("second")); e == nil {
		t.Fatal("existing file overwritten")
	}
	b, e := os.ReadFile(filepath.Join(root, "exclusive"))
	if e != nil || string(b) != "first" {
		t.Fatal("exclusive creation changed existing bytes")
	}
}

func TestWorktreeDiagnostics(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	version := "0.1.15-SNAPSHOT-" + sha[:7]
	writeFixture(t, filepath.Join(root, "plugin.json"), []byte(strings.Replace(string(before.Manifest), "0.1.10", version, 1)))
	writeFixture(t, filepath.Join(root, "dist/allowed"), []byte("inert ignored output"))
	if e := sourceStatus(root, true); e != nil {
		t.Fatal("existing allowed status changed:", e)
	}
	if e := sourceStatus(root, false); e == nil || !strings.Contains(e.Error(), "phase=pre-build") {
		t.Fatal("pre-build diagnostics missing")
	}
	original, e := os.ReadFile(filepath.Join(root, "go.mod"))
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "go.mod"), append(append([]byte(nil), original...), []byte("// private-value-must-not-be-logged\n")...))
	e = sourceStatus(root, true)
	if e == nil {
		t.Fatal("unexpected source change accepted")
	}
	for _, want := range []string{"phase=post-build", "category=worktree-modified", "xy_hex=204d", "path=go.mod", "path_sha256=" + checksumBytes([]byte("go.mod"))} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("missing bounded status field %q: %s", want, e)
		}
	}
	if strings.Contains(e.Error(), "private-value-must-not-be-logged") {
		t.Fatal("file contents logged")
	}
	writeFixture(t, filepath.Join(root, "go.mod"), original)
	privatePath := "private-client-value\n::error::do-not-print"
	writeFixture(t, filepath.Join(root, privatePath), []byte("private-content-value"))
	e = sourceStatus(root, true)
	if e == nil {
		t.Fatal("unknown path accepted")
	}
	for _, want := range []string{"category=untracked", "xy_hex=3f3f", "path=redacted", "path_sha256=" + checksumBytes([]byte(privatePath))} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("missing redacted diagnostic %q: %s", want, e)
		}
	}
	if len(e.Error()) > 320 || strings.ContainsAny(e.Error(), "\n\r") || strings.Contains(e.Error(), "private-client") || strings.Contains(e.Error(), "::error::") {
		t.Fatal("unbounded/raw path diagnostics")
	}
}

func TestArchiveReceiptPrivacy(t *testing.T) {
	i := fixtureInfo()
	i.Main.Version = "private-main-version"
	i.Main.Sum = "private-main-sum"
	i.Main.Replace = &debug.Module{Path: "private-replacement-path"}
	i.Deps = []*debug.Module{{Path: "private-dependency-path", Version: "private-dependency-version", Sum: "private-dependency-sum"}}
	i.Settings = append(i.Settings, debug.BuildSetting{Key: "private-setting", Value: "private-setting-value"})
	i.Settings[6].Value += " -X unrelated.secret=private-linker-value"
	b, e := json.Marshal(verifiedArchive{Target: "linux-amd64", BuildInfo: i})
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("private-")) || bytes.Contains(b, []byte("unrelated.secret")) || bytes.Contains(b, []byte("-ldflags")) {
		t.Fatal("receipt emitted unnecessary private dependency/build fields")
	}
	var decoded verifiedArchive
	if e = json.Unmarshal(b, &decoded); e != nil || decoded.BuildInfo == nil {
		t.Fatal("public build facts missing")
	}
	if decoded.BuildInfo.GoVersion != "go1.27.4" || decoded.BuildInfo.Path != archiveModule+"/cmd/"+archivePlugin || decoded.BuildInfo.Main.Path != archiveModule {
		t.Fatal("required public compiler/command/module facts lost")
	}
	want := map[string]string{"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "vcs": "git", "vcs.revision": strings.Repeat("a", 40), "vcs.modified": "true"}
	for _, s := range decoded.BuildInfo.Settings {
		if want[s.Key] != s.Value {
			t.Fatal("unexpected public build setting")
		}
		delete(want, s.Key)
	}
	if len(want) != 0 {
		t.Fatal("public provenance facts missing")
	}
}

func TestMalformedWorktreeDiagnostics(t *testing.T) {
	for _, row := range [][]byte{nil, []byte("x"), []byte("private malformed value\n::error::"), append([]byte("?? "), bytes.Repeat([]byte("private-marker"), 10000)...)} {
		e := unexpectedWorktreeChange(row, true)
		if e == nil || len(e.Error()) > 320 || strings.ContainsAny(e.Error(), "\n\r") || strings.Contains(e.Error(), "private-marker") || strings.Contains(e.Error(), "private malformed") {
			t.Fatal("malformed status leaked or exceeded bound")
		}
	}
}

func TestWorktreeDiagnosticsEntryPoint(t *testing.T) {
	root, sha, _ := newSourceFixture(t)
	owned := t.TempDir()
	state := filepath.Join(owned, "before.json")
	script, e := filepath.Abs("check-release-archives.go")
	if e != nil {
		t.Fatal(e)
	}
	fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "capture", sha, state)
	meta := releaseMetadata{Project: archivePlugin, Version: "0.1.15-SNAPSHOT-" + sha[:7], Commit: sha}
	meta.Runtime.OS = runtime.GOOS
	meta.Runtime.Arch = runtime.GOARCH
	b, e := json.Marshal(meta)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "dist/metadata.json"), b)
	mod, e := os.ReadFile(filepath.Join(root, "go.mod"))
	if e != nil {
		t.Fatal(e)
	}
	privatePath := "unknown-private-value\n::error::do-not-log"
	for _, tc := range []struct {
		name, category, path string
		change, restore      func()
	}{
		{"known", "worktree-modified", "go.mod", func() {
			writeFixture(t, filepath.Join(root, "go.mod"), append(append([]byte(nil), mod...), []byte("// private-content-marker\n")...))
		}, func() { writeFixture(t, filepath.Join(root, "go.mod"), mod) }},
		{"redacted", "untracked", privatePath, func() { writeFixture(t, filepath.Join(root, privatePath), []byte("private-content-marker")) }, func() {
			if e := os.Remove(filepath.Join(root, privatePath)); e != nil {
				t.Fatal(e)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			defer tc.restore()
			c := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "run", script, "verify", sha, state, filepath.Join(owned, "extract-"+tc.name))
			c.Dir = root
			c.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
			var out, errout boundedOutput
			c.Stdout = &out
			c.Stderr = &errout
			err := c.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || out.b.Len() != 0 || out.overflow || errout.overflow {
				t.Fatalf("actual verifier refusal exit/stdout mismatch: %v", err)
			}
			for _, want := range []string{"archive qualification: unexpected source/worktree change:", "phase=post-build", "category=" + tc.category, "path_sha256=" + checksumBytes([]byte(tc.path))} {
				if !strings.Contains(errout.b.String(), want) {
					t.Errorf("actual entry point missing %q", want)
				}
			}
			if strings.Contains(errout.b.String(), "unknown-private-value") || strings.Contains(errout.b.String(), "private-content-marker") || strings.Contains(errout.b.String(), "::error::") {
				t.Fatal("actual stderr disclosed fixture values")
			}
			if _, e := os.Lstat(filepath.Join(owned, "extract-"+tc.name)); !os.IsNotExist(e) {
				t.Fatal("source refusal created extraction output")
			}
		})
	}
}

func TestCaptureRawSource(t *testing.T) {
	root, sha, _ := newSourceFixture(t)
	fixtureGit(t, root, "update-index", "--assume-unchanged", "internal/version.go")
	writeFixture(t, filepath.Join(root, "internal/version.go"), []byte("package internal\nvar Version=\"hidden\"\n"))
	if _, e := captureSource(root, sha); e == nil {
		t.Fatal("Git-clean but raw-different source accepted")
	}
}

func TestJSONAndPathRefusals(t *testing.T) {
	for _, b := range []string{`{"x":1,"x":2}`, `{"x":{"y":1,"y":2}}`, `{} {}`, `[`, strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		if _, e := jsonValue([]byte(b)); e == nil {
			t.Fatal("ambiguous or malformed JSON accepted")
		}
	}
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "plain"), []byte("bytes"))
	if _, e := regularPath(root, "plain", 10); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"../plain", "./plain", "/plain", "plain/../plain", "plain\n", "plain\\"} {
		if _, e := regularPath(root, n, 10); e == nil {
			t.Fatal("noncanonical path accepted")
		}
	}
	if _, e := readRegular(root, "plain", 2); e == nil {
		t.Fatal("oversize file accepted")
	}
	if e := os.Symlink("plain", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := regularPath(root, "link", 10); e == nil {
		t.Fatal("nonregular input accepted")
	}
	var out boundedOutput
	p := bytes.Repeat([]byte{'x'}, maxMetadata+1)
	n, e := out.Write(p)
	if e != nil || n != len(p) || !out.overflow || out.b.Len() != maxMetadata {
		t.Fatal("bounded accepting output failed")
	}
}

func fixtureTool(t *testing.T, root string, env []string, args ...string) []byte {
	t.Helper()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	c := exec.Command(goTool, args...)
	c.Dir = root
	c.Env = append(os.Environ(), append([]string{"GO111MODULE=on", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "CGO_ENABLED=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}, env...)...)
	var out, errout boundedOutput
	c.Stdout = &out
	c.Stderr = &errout
	if e := c.Run(); e != nil || out.overflow || errout.overflow {
		t.Fatalf("finite synthetic fixture compiler/verifier failed: %v %s", e, errout.b.String())
	}
	return out.b.Bytes()
}

func packFixture(t *testing.T, binary, manifest []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		data []byte
	}{{archivePlugin, binary}, {"plugin.json", manifest}} {
		if e := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(f.data); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}

// This runs real Git, real compiler metadata and the actual validator CLI on
// synthetic application bytes. No compiled/archived binary is ever launched,
// and it is not evidence that GoReleaser produced a real plugin archive.
func TestRealArchiveProvenance(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	owned := t.TempDir()
	clean := filepath.Join(owned, "clean-binary")
	fixtureTool(t, root, nil, "build", "-p=1", "-mod=readonly", "-buildvcs=true", "-o", clean, "./cmd/workflow-plugin-compute")
	info, e := buildinfo.ReadFile(clean)
	if e != nil {
		t.Fatal(e)
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["vcs.revision"] != sha || settings["vcs.modified"] != "false" {
		t.Fatal("clean synthetic Git source provenance not recorded")
	}
	script, e := filepath.Abs("check-release-archives.go")
	if e != nil {
		t.Fatal(e)
	}
	stateFile := filepath.Join(owned, "before.json")
	fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "capture", sha, stateFile)
	version := "0.1.15-SNAPSHOT-" + sha[:7]
	manifest := []byte(strings.Replace(string(before.Manifest), "0.1.10", version, 1))
	writeFixture(t, filepath.Join(root, "plugin.json"), manifest)
	var artifacts []releaseArtifact
	checksums := ""
	for _, target := range targets {
		parts := strings.Split(target, "-")
		rel := "dist/" + target + "/" + archivePlugin
		bin := filepath.Join(root, filepath.FromSlash(rel))
		fixtureTool(t, root, []string{"GOOS=" + parts[0], "GOARCH=" + parts[1]}, "build", "-p=1", "-mod=readonly", "-buildvcs=true", "-ldflags=-s -w -X "+archiveModule+"/internal.Version="+version, "-o", bin, "./cmd/workflow-plugin-compute")
		b, e := os.ReadFile(bin)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = inspectArchiveBinary(b, target, sha, version); e != nil {
			t.Fatal(e)
		}
		// Change only the copied native header's machine identifier. Build info
		// still parses and claims the right target; the object-header gate must
		// independently reject that contradiction. These bytes are never run.
		wrongHeader := append([]byte(nil), b...)
		if target == "linux-amd64" {
			binary.LittleEndian.PutUint16(wrongHeader[18:20], 183)
		} else {
			binary.LittleEndian.PutUint32(wrongHeader[4:8], 0x1000007)
		}
		stillInfo, e := buildinfo.Read(bytes.NewReader(wrongHeader))
		if e != nil {
			t.Fatal(e)
		}
		if e = checkArchiveInfo(stillInfo, target, sha, version); e != nil {
			t.Fatal("header control changed metadata")
		}
		if _, e = inspectArchiveBinary(wrongHeader, target, sha, version); e == nil {
			t.Fatal("object header contradicting build metadata accepted")
		}
		packed := packFixture(t, b, manifest)
		writeFixture(t, filepath.Join(root, "dist", archiveName(target)), packed)
		checksums += checksumBytes(packed) + "  " + archiveName(target) + "\n"
		artifacts = append(artifacts, releaseArtifact{Name: archivePlugin, Path: rel, OS: parts[0], Arch: parts[1], Type: "Binary", Internal: 4}, releaseArtifact{Name: archiveName(target), Path: "dist/" + archiveName(target), OS: parts[0], Arch: parts[1], Type: "Archive", Internal: 1})
	}
	meta := releaseMetadata{Project: archivePlugin, Version: version, Commit: sha, Date: "2000-01-01T00:00:00Z"}
	meta.Runtime.OS = runtime.GOOS
	meta.Runtime.Arch = runtime.GOARCH
	metadata, e := json.Marshal(meta)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "dist/metadata.json"), metadata)
	effective := []byte("# Synthetic metadata fixture; no GoReleaser execution.\nversion: 2\nproject_name: workflow-plugin-compute\n")
	writeFixture(t, filepath.Join(root, "dist/config.yaml"), effective)
	writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(checksums))
	artifacts = append(artifacts, releaseArtifact{Name: "checksums.txt", Path: "dist/checksums.txt", Type: "Checksum", Internal: 12}, releaseArtifact{Name: "metadata.json", Path: "dist/metadata.json", Type: "Metadata", Internal: 35})
	index, e := json.Marshal(artifacts)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index)
	output := fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "verify", sha, stateFile, filepath.Join(owned, "extracted"))
	var report archiveReport
	if e = decodeExact(output, &report); e != nil || len(report.Archives) != 2 || report.Commit != sha {
		t.Fatalf("actual CLI refused synthetic producer bytes: %v", e)
	}
	t.Run("effective-config-binding", func(t *testing.T) {
		var envelope map[string]json.RawMessage
		if e := json.Unmarshal(output, &envelope); e != nil {
			t.Fatal(e)
		}
		for key, want := range map[string]string{"effective_config": string(effective), "effective_config_sha256": checksumBytes(effective), "metadata_sha256": checksumBytes(metadata), "artifact_index_sha256": checksumBytes(index), "checksums_sha256": checksumBytes([]byte(checksums))} {
			var got string
			if e := json.Unmarshal(envelope[key], &got); e != nil || got != want {
				t.Errorf("actual %s not bound in report", key)
			}
		}
	})
	existing := filepath.Join(owned, "existing-extract")
	writeFixture(t, filepath.Join(existing, "sentinel"), []byte("preserve"))
	if _, e = verifySnapshot(root, sha, before, existing); e == nil {
		t.Fatal("preexisting extraction path reused")
	}
	if b, e := os.ReadFile(filepath.Join(existing, "sentinel")); e != nil || string(b) != "preserve" {
		t.Fatal("existing extraction owner was modified")
	}
	for _, tc := range []struct {
		name            string
		mutate, restore func()
	}{
		{"digest", func() {
			writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(strings.Repeat("0", 64)+checksums[64:]))
		}, func() { writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(checksums)) }},
		{"metadata", func() {
			bad := meta
			bad.Commit = strings.Repeat("b", 40)
			b, _ := json.Marshal(bad)
			writeFixture(t, filepath.Join(root, "dist/metadata.json"), b)
		}, func() { writeFixture(t, filepath.Join(root, "dist/metadata.json"), metadata) }},
		{"binding", func() {
			bad := append([]releaseArtifact(nil), artifacts...)
			bad[0].Path, bad[2].Path = bad[2].Path, bad[0].Path
			b, _ := json.Marshal(bad)
			writeFixture(t, filepath.Join(root, "dist/artifacts.json"), b)
		}, func() { writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index) }},
		{"wire-type", func() {
			bad := append([]releaseArtifact(nil), artifacts...)
			bad[0].Internal = 1
			b, _ := json.Marshal(bad)
			writeFixture(t, filepath.Join(root, "dist/artifacts.json"), b)
		}, func() { writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index) }},
		{"unlisted-archive", func() { writeFixture(t, filepath.Join(root, "dist/unlisted.tar.gz"), []byte("inert")) }, func() {
			if e := os.Remove(filepath.Join(root, "dist/unlisted.tar.gz")); e != nil {
				t.Fatal(e)
			}
		}},
		{"unlisted-file", func() { writeFixture(t, filepath.Join(root, "dist/unlisted"), []byte("inert")) }, func() {
			if e := os.Remove(filepath.Join(root, "dist/unlisted")); e != nil {
				t.Fatal(e)
			}
		}},
		{"unlisted-link", func() {
			if e := os.Symlink(archiveName(targets[0]), filepath.Join(root, "dist/unlisted-link")); e != nil {
				t.Fatal(e)
			}
		}, func() {
			if e := os.Remove(filepath.Join(root, "dist/unlisted-link")); e != nil {
				t.Fatal(e)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.mutate()
			defer tc.restore()
			extract := filepath.Join(owned, "refusal-"+tc.name)
			if _, e := verifySnapshot(root, sha, before, extract); e == nil {
				t.Fatal("wrong full snapshot fixture accepted")
			}
			if _, e := os.Lstat(extract); !os.IsNotExist(e) {
				t.Fatal("failed extraction root left behind")
			}
		})
	}
	if _, e := verifySource(root, sha, version, before); e != nil {
		t.Fatal(e)
	}
	t.Logf("synthetic source=%s tree=%s; real clean and dirty VCS metadata, Linux/amd64 and Darwin/arm64, actual validator CLI; zero archived execution", sha, before.Tree)
}
