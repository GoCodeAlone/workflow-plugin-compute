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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
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
		"version: v2.20.3", "install-only: true", "GOTOOLCHAIN: local",
		"v?2[.]20[.]3",
		"check --config=.goreleaser.yaml", "release --config=.goreleaser.yaml --snapshot --clean",
		"--skip=publish,sign,notarize,sbom,docker,ko --parallelism=1 --timeout=10m",
		"GOPROXY=off", "GOVCS='*:off'", "GOSUMDB=off", "env -i",
		"check-release-archives.go capture", "check-release-archives.go verify",
		"extracted/linux-amd64/workflow-plugin-compute", "extracted/darwin-arm64/workflow-plugin-compute",
		"authenticated engine bytes", "tag-mode qualification",
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

func TestArchiveReleaseEngineParity(t *testing.T) {
	for _, name := range []string{"archive-qualification.yml", "release.yml"} {
		b, err := os.ReadFile("../.github/workflows/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{
			"goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de",
			"version: v2.20.3",
			"d124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d",
			"shasum -a 256 --check --strict",
			"test -f \"$ENGINE_BIN\" && test ! -L \"$ENGINE_BIN\"",
		} {
			count := 1
			if name == "release.yml" && required == "shasum -a 256 --check --strict" {
				// wfctl is authenticated independently too. Bind this assertion
				// to the engine's exact guard, not a file-wide checksum count.
				engineGuard := `printf '%s  %s\n' 'd124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d' "$ENGINE_BIN" | shasum -a 256 --check --strict`
				if strings.Count(string(b), engineGuard) != 1 {
					t.Error("release must authenticate the exact engine path")
				}
				continue
			}
			if name == "archive-qualification.yml" && (strings.HasPrefix(required, "d124") || strings.Contains(required, "shasum") || strings.HasPrefix(required, "test -f")) {
				count = 2 // pre-credential binding and pre-execution recheck
			}
			if strings.Count(string(b), required) != count {
				t.Errorf("%s must pin the shared engine contract: %s", name, required)
			}
		}
		if name == "archive-qualification.yml" {
			for _, required := range []string{"verify_engine\n          \"$ENGINE_BIN\" --version", "clean \"$ENGINE_BIN\" \"$@\"", "checked_engine check --config", "checked_engine release --config", "ENGINE_BIN: ${{ steps.scratch.outputs.engine_bin }}"} {
				if !strings.Contains(string(b), required) {
					t.Errorf("archive engine binding missing: %s", required)
				}
			}
		} else if strings.Contains(string(b), "args: release --clean") || !strings.Contains(string(b), "verify_engine\n          \"$ENGINE_BIN\" release --clean") || !strings.Contains(string(b), "install-only: true") {
			t.Error("release must install without execution, then verify and use the same absolute engine")
		}
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
		{"old-engine", "version: v2.20.3", "version: v2.16.0"},
		{"old-engine-guard", "v?2[.]20[.]3", "v?2[.]16[.]0"},
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
	for _, n := range []string{".goreleaser.yaml", "scripts/check-build-toolchain.go", "go.mod", "go.sum", "scripts/check-release-archives.go", "scripts/check-release-archives_test.go", "scripts/check-native-release.go", "scripts/check-native-release_test.go"} {
		data, e := os.ReadFile(filepath.Join("..", n))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Count(string(b), checksumBytes(data)+"  "+n) != 2 {
			t.Errorf("both pre-acquisition and packaging anchors must match %s", n)
		}
	}
}

func TestNativeReleaseHookContract(t *testing.T) {
	b, err := os.ReadFile("../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compiler := strings.Index(string(b), `go run ./scripts/check-build-toolchain.go "{{ .Path }}"`)
	gate := strings.Index(string(b), `env GOOS= GOARCH= go run ./scripts/check-native-release.go "{{ .Os }}" "{{ .Arch }}" "{{ .Path }}" "{{ .IsSnapshot }}"`)
	if compiler < 0 || gate <= compiler {
		t.Fatal("native release check must be a real post-build hook after compiler validation")
	}
	b, err = os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8",
		"WFCTL_BIN: ${{ runner.temp }}/wfctl-bin/wfctl",
		"shasum -a 256 --check --strict",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("release verifier authentication/input missing: %s", required)
		}
	}
	digest := strings.Index(s, "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8")
	chmod := strings.Index(s, `chmod 500 "${RUNNER_TEMP}/wfctl-bin/wfctl"`)
	if chmod <= digest || strings.Contains(s, "skipping verify-capabilities") || strings.Contains(s, "Verify capabilities (runtime truth-check)") {
		t.Fatal("wfctl must be authenticated before chmod and checking must not remain after publication")
	}
}

func TestTagPRQualificationWorkflow(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/tag-qualification.yml")
	if err != nil {
		t.Fatalf("read-only tag qualification execution path missing: %v", err)
	}
	s := string(b)
	for _, required := range []string{"  pull_request:", "  contents: read", "persist-credentials: false", "cache: false", "github.event.pull_request.head.repo.full_name == github.repository", "qualify-tag-archives.go", "Acquire pinned dependencies", "env -i", "GOTOOLCHAIN=local", "GOAUTH=off", "GOPROXY=off", "GOVCS='*:off'", "install-release-engine.sh", "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8"} {
		if !strings.Contains(s, required) {
			t.Fatalf("tag job contract missing %s", required)
		}
	}
	for _, forbidden := range []string{"contents: write", "pull_request_target:", "workflow_dispatch:", "repository_dispatch:", "  push:", "upload-artifact", "packages:", "id-token:", "goreleaser-action", "--snapshot", "--skip=validate"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("tag job contains forbidden operation %s", forbidden)
		}
	}
	if strings.Count(s, "secrets.RELEASES_TOKEN") != 1 {
		t.Fatal("tag job changes dependency credential scope")
	}
	a, z := strings.Index(s, "      - name: Acquire pinned dependencies"), strings.Index(s, "      - name: Execute tag qualification without credentials")
	if a < 0 || z <= a {
		t.Fatal("tag job acquisition/execution boundary missing")
	}
	for _, forbidden := range []string{"go run", "go test", "scripts/", "wfctl ", "goreleaser "} {
		if strings.Contains(s[a:z], forbidden) {
			t.Fatal("project code executes during credential acquisition")
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

func TestTagModeCaptureCLI(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	tag := qualificationTagReference(t, sha)
	// This is an unsigned, disposable local ref; no signing or remote operation.
	fixtureGit(t, root, "tag", "--no-sign", tag, sha)
	script, e := filepath.Abs("check-release-archives.go")
	if e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(t.TempDir(), "tag-source.json")
	fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "capture-tag", sha, before.Tree, tag, state)
	b, e := os.ReadFile(state)
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct {
		Source *sourceState `json:"source"`
		Tag    string       `json:"tag"`
	}
	if e = decodeExact(b, &receipt); e != nil || receipt.Source == nil || receipt.Tag != tag || receipt.Source.Commit != sha || receipt.Source.Tree != before.Tree || !bytes.Equal(receipt.Source.Manifest, before.Manifest) {
		t.Fatalf("actual tag capture did not bind exact source/tree/tag/raw manifest: %v", e)
	}
}

// Tag-mode verifier proof uses genuine local Git tags and compiler metadata,
// not an engine invocation, native plugin execution or publication.
func TestTagModeArchiveCLI(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	tag := qualificationTagReference(t, sha)
	version := strings.TrimPrefix(tag, "v")
	fixtureGit(t, root, "tag", "--no-sign", tag, sha)
	script, e := filepath.Abs("check-release-archives.go")
	if e != nil {
		t.Fatal(e)
	}
	owned := t.TempDir()
	state, legacy := filepath.Join(owned, "tag-state.json"), filepath.Join(owned, "snapshot-state.json")
	fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "capture-tag", sha, before.Tree, tag, state)
	fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "capture", sha, legacy)
	manifest := bytes.Replace(before.Manifest, []byte("0.1.10"), []byte(version), 1)
	writeFixture(t, filepath.Join(root, "plugin.json"), manifest)
	var artifacts []releaseArtifact
	checksums := ""
	binaries, packed := map[string][]byte{}, map[string][]byte{}
	for _, target := range targets {
		parts := strings.Split(target, "-")
		rel := "dist/" + target + "/" + archivePlugin
		bin := filepath.Join(root, filepath.FromSlash(rel))
		fixtureTool(t, root, []string{"GOOS=" + parts[0], "GOARCH=" + parts[1]}, "build", "-p=1", "-mod=readonly", "-buildvcs=true", "-ldflags=-s -w -X "+archiveModule+"/internal.Version="+version, "-o", bin, "./cmd/workflow-plugin-compute")
		binaries[target], e = os.ReadFile(bin)
		if e != nil {
			t.Fatal(e)
		}
		packed[target] = packFixture(t, binaries[target], manifest)
		writeFixture(t, filepath.Join(root, "dist", archiveName(target)), packed[target])
		checksums += checksumBytes(packed[target]) + "  " + archiveName(target) + "\n"
		artifacts = append(artifacts, releaseArtifact{Name: archivePlugin, Path: rel, OS: parts[0], Arch: parts[1], Type: "Binary", Internal: 4}, releaseArtifact{Name: archiveName(target), Path: "dist/" + archiveName(target), OS: parts[0], Arch: parts[1], Type: "Archive", Internal: 1})
	}
	meta := releaseMetadata{Project: archivePlugin, Tag: tag, Version: version, Commit: sha, Date: "2000-01-01T00:00:00Z"}
	meta.Runtime.OS, meta.Runtime.Arch = runtime.GOOS, runtime.GOARCH
	metadata, _ := json.Marshal(meta)
	writeFixture(t, filepath.Join(root, "dist/metadata.json"), metadata)
	writeFixture(t, filepath.Join(root, "dist/config.yaml"), []byte("# Synthetic tag-mode fixture; no engine invocation.\nversion: 2\n"))
	writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(checksums))
	artifacts = append(artifacts, releaseArtifact{Name: "checksums.txt", Path: "dist/checksums.txt", Type: "Checksum", Internal: 12}, releaseArtifact{Name: "metadata.json", Path: "dist/metadata.json", Type: "Metadata", Internal: 36})
	index, _ := json.Marshal(artifacts)
	writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index)
	verifyArgs := []string{"verify-tag", sha, before.Tree, tag, state}
	output := fixtureTool(t, root, []string{"GO111MODULE=off"}, append([]string{"run", script}, append(append([]string{}, verifyArgs...), filepath.Join(owned, "extracted"))...)...)
	var report archiveReport
	if e = decodeExact(output, &report); e != nil || report.Tree != before.Tree || report.Commit != sha || len(report.Archives) != 2 {
		t.Fatalf("tag-mode CLI rejected genuine synthetic binding: %v", e)
	}
	var envelope map[string]json.RawMessage
	if e = json.Unmarshal(output, &envelope); e != nil {
		t.Fatal(e)
	}
	for key, want := range map[string]string{"tag": tag, "tag_version": version, "verification_mode": "local-tag"} {
		var got string
		if e = json.Unmarshal(envelope[key], &got); e != nil || got != want {
			t.Fatalf("tag report field %s not bound", key)
		}
	}
	if _, ok := envelope["snapshot_version"]; ok {
		t.Fatal("tag report was mislabeled snapshot")
	}
	for _, a := range report.Archives {
		if a.BinarySHA != checksumBytes(binaries[a.Target]) {
			t.Fatal("tag-mode binary hash not bound to compiled artifact")
		}
	}

	reject := func(t *testing.T, name string, args, env []string, diagnostic string) {
		t.Helper()
		extract := filepath.Join(owned, "refusal-"+name)
		argv := append([]string{"run", script}, append(append([]string{}, args...), extract)...)
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), argv...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), append([]string{"GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}, env...)...)
		var out, errout boundedOutput
		cmd.Stdout, cmd.Stderr = &out, &errout
		err := cmd.Run()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || out.b.Len() != 0 || out.overflow || errout.overflow || !strings.Contains(errout.b.String(), diagnostic) {
			t.Fatalf("actual tag-mode refusal %s missing: %v %q", name, err, errout.b.String())
		}
		if _, e := os.Lstat(extract); !os.IsNotExist(e) {
			t.Fatal("tag refusal left extraction output")
		}
	}
	for _, name := range []string{"wrong-tree", "wrong-tag", "legacy-receipt", "nil-source", "wrong-receipt-tag", "snapshot-command", "current-tag-env", "previous-tag-env"} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{}, verifyArgs...)
			env := []string{}
			want := "tag source receipt mismatch"
			switch name {
			case "wrong-tree":
				args[2] = strings.Repeat("0", 40)
			case "wrong-tag":
				args[3] = tag + ".extra"
				want = "qualification tag/source mismatch"
			case "legacy-receipt":
				args[4] = legacy
				want = "unknown field"
			case "nil-source", "wrong-receipt-tag":
				b, e := os.ReadFile(state)
				if e != nil {
					t.Fatal(e)
				}
				var bad map[string]json.RawMessage
				if e = json.Unmarshal(b, &bad); e != nil {
					t.Fatal(e)
				}
				if name == "nil-source" {
					bad["source"] = json.RawMessage("null")
				} else {
					bad["tag"], _ = json.Marshal(tag + ".extra")
				}
				b, e = json.Marshal(bad)
				if e != nil {
					t.Fatal(e)
				}
				args[4] = filepath.Join(owned, name+".json")
				writeFixture(t, args[4], b)
			case "snapshot-command":
				args = []string{"verify", sha, state}
				want = "unknown field"
			case "current-tag-env":
				env = []string{"GORELEASER_CURRENT_TAG="}
				want = "qualification tag override environment"
			case "previous-tag-env":
				env = []string{"GORELEASER_PREVIOUS_TAG="}
				want = "qualification tag override environment"
			}
			reject(t, name, args, env, want)
		})
	}
	ref := "refs/tags/" + tag
	t.Run("missing-ref", func(t *testing.T) {
		fixtureGit(t, root, "update-ref", "-d", ref, sha)
		defer fixtureGit(t, root, "tag", "--no-sign", tag, sha)
		reject(t, "missing-ref", verifyArgs, nil, "qualification tag ref mismatch")
	})
	t.Run("moved-ref", func(t *testing.T) {
		other := fixtureGit(t, root, "commit-tree", before.Tree, "-p", sha, "-m", "inert other commit")
		fixtureGit(t, root, "update-ref", ref, other, sha)
		defer fixtureGit(t, root, "update-ref", ref, sha, other)
		reject(t, "moved-ref", verifyArgs, nil, "qualification tag ref mismatch")
	})
	t.Run("annotated-ref", func(t *testing.T) {
		fixtureGit(t, root, "update-ref", "-d", ref, sha)
		fixtureGit(t, root, "tag", "--no-sign", "-a", tag, "-m", "inert annotation", sha)
		defer func() { fixtureGit(t, root, "tag", "-d", tag); fixtureGit(t, root, "tag", "--no-sign", tag, sha) }()
		reject(t, "annotated-ref", verifyArgs, nil, "qualification tag ref mismatch")
	})
	t.Run("symbolic-ref", func(t *testing.T) {
		fixtureGit(t, root, "symbolic-ref", ref, "refs/heads/main")
		defer func() {
			fixtureGit(t, root, "symbolic-ref", "--delete", ref)
			fixtureGit(t, root, "tag", "--no-sign", tag, sha)
		}()
		reject(t, "symbolic-ref", verifyArgs, nil, "qualification tag ref mismatch")
	})
	t.Run("extra-annotated-ref", func(t *testing.T) {
		extra := tag + ".extra"
		fixtureGit(t, root, "tag", "--no-sign", "-a", extra, "-m", "inert additional annotation", sha)
		defer fixtureGit(t, root, "tag", "-d", extra)
		reject(t, "extra-annotated-ref", verifyArgs, nil, "ambiguous qualification tag")
	})
	for _, name := range []string{"metadata-tag", "metadata-snapshot-version", "checksum", "wire-type", "extra-output"} {
		t.Run(name, func(t *testing.T) {
			want := "tag metadata version/source mismatch"
			switch name {
			case "metadata-tag", "metadata-snapshot-version":
				bad := meta
				if name == "metadata-tag" {
					bad.Tag = tag + ".extra"
				} else {
					bad.Version = "0.1.15-SNAPSHOT-" + sha[:7]
				}
				b, _ := json.Marshal(bad)
				writeFixture(t, filepath.Join(root, "dist/metadata.json"), b)
				defer writeFixture(t, filepath.Join(root, "dist/metadata.json"), metadata)
			case "checksum":
				writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(strings.Repeat("0", 64)+checksums[64:]))
				defer writeFixture(t, filepath.Join(root, "dist/checksums.txt"), []byte(checksums))
				want = "archive checksum mismatch"
			case "wire-type":
				bad := append([]releaseArtifact{}, artifacts...)
				bad[len(bad)-1].Internal = 35
				b, _ := json.Marshal(bad)
				writeFixture(t, filepath.Join(root, "dist/artifacts.json"), b)
				defer writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index)
				want = "artifact wire type mismatch"
			case "extra-output":
				p := filepath.Join(root, "dist/unlisted")
				writeFixture(t, p, []byte("inert"))
				defer os.Remove(p)
				want = "unindexed or nonregular dist output"
			}
			reject(t, name, verifyArgs, nil, want)
		})
	}
	t.Run("native-receipt-binding-synthetic-facts", func(t *testing.T) {
		// Only receipt-consumer proof. These synthetic success facts do not
		// establish a wfctl/plugin invocation; hosted CI must produce them.
		reportPath, nativePath := filepath.Join(owned, "tag-report.json"), filepath.Join(owned, "native-facts.json")
		writeFixture(t, reportPath, output)
		native := nativeValidationReceipt{Schema: 1, Scope: "runtime-identity-version-declared-iac", Verdict: "pass", Target: "linux-amd64", Artifact: "dist/linux-amd64/" + archivePlugin, ArtifactSHA: checksumBytes(binaries["linux-amd64"]), ManifestSHA: checksumBytes(manifest), VerifierSHA: "0d41f3050b535e2bc7c1d6a5537ab2a60938e0b49c4c4f12ece1be883762dfc8"}
		good, _ := json.Marshal(native)
		writeFixture(t, nativePath, good)
		args := []string{"run", script, "bind-native", sha, before.Tree, tag, reportPath, nativePath}
		bound := fixtureTool(t, root, []string{"GO111MODULE=off"}, args...)
		var facts map[string]json.RawMessage
		if e := json.Unmarshal(bound, &facts); e != nil {
			t.Fatal(e)
		}
		for key, want := range map[string]string{"binary_sha256": native.ArtifactSHA, "manifest_sha256": native.ManifestSHA, "verifier_sha256": native.VerifierSHA, "archive_receipt_sha256": checksumBytes(output), "native_receipt_sha256": checksumBytes(good)} {
			var got string
			if e := json.Unmarshal(facts[key], &got); e != nil || got != want {
				t.Fatalf("combined receipt %s not bound", key)
			}
		}
		for _, name := range []string{"scope", "verdict", "schema", "tool", "artifact", "manifest", "binary", "unknown"} {
			t.Run(name, func(t *testing.T) {
				var bad map[string]any
				if e := json.Unmarshal(good, &bad); e != nil {
					t.Fatal(e)
				}
				want := "native receipt contract mismatch"
				switch name {
				case "scope":
					bad["scope"] = "full-capability-parity"
				case "verdict":
					bad["verdict"] = "fail"
				case "schema":
					bad["schema"] = 2
				case "tool":
					bad["verifier_sha256"] = strings.Repeat("0", 64)
				case "artifact":
					bad["artifact_path"] = "dist/darwin-arm64/" + archivePlugin
					want = "native artifact path/index mismatch"
				case "manifest":
					bad["manifest_sha256"] = strings.Repeat("0", 64)
				case "binary":
					bad["artifact_sha256"] = strings.Repeat("0", 64)
					want = "native artifact bytes changed"
				case "unknown":
					bad["unrecognized_private_marker"] = true
					want = "unknown field"
				}
				b, _ := json.Marshal(bad)
				writeFixture(t, nativePath, b)
				defer writeFixture(t, nativePath, good)
				cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), args...)
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off")
				var out, errout boundedOutput
				cmd.Stdout, cmd.Stderr = &out, &errout
				e := cmd.Run()
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || out.b.Len() != 0 || out.overflow || errout.overflow || !strings.Contains(errout.b.String(), want) {
					t.Fatalf("binder refusal %s missing: %v %q", name, e, errout.b.String())
				}
			})
		}

		for _, name := range []string{"report-extra-dependency", "report-extra-main-version", "report-extra-setting"} {
			t.Run(name, func(t *testing.T) {
				var raw map[string]any
				if e := json.Unmarshal(output, &raw); e != nil {
					t.Fatal(e)
				}
				info := raw["archives"].([]any)[0].(map[string]any)["build_info"].(map[string]any)
				switch name {
				case "report-extra-dependency":
					info["Deps"] = []any{map[string]any{"Path": "inert-extra-module"}}
				case "report-extra-main-version":
					info["Main"].(map[string]any)["Version"] = "inert-extra-version"
				case "report-extra-setting":
					info["Settings"] = append(info["Settings"].([]any), map[string]any{"Key": "inert-extra-setting", "Value": "inert-extra-value"})
				}
				b, _ := json.Marshal(raw)
				writeFixture(t, reportPath, b)
				defer writeFixture(t, reportPath, output)
				cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), args...)
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off")
				var out, errout boundedOutput
				cmd.Stdout, cmd.Stderr = &out, &errout
				e := cmd.Run()
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || out.b.Len() != 0 || out.overflow || errout.overflow || !strings.Contains(errout.b.String(), "tag archive report changed") {
					t.Fatalf("raw report difference was lost: %v %q", e, errout.b.String())
				}
			})
		}

		for _, name := range []string{"stale-linux-archive", "stale-darwin-archive", "missing-linux-archive", "missing-darwin-archive", "changed-metadata", "changed-checksum-order", "changed-effective-config", "unindexed-output"} {
			t.Run(name, func(t *testing.T) {
				path := "dist/" + archiveName("linux-amd64")
				want := "tag archive revalidation failed"
				switch name {
				case "stale-darwin-archive", "missing-darwin-archive":
					path = "dist/" + archiveName("darwin-arm64")
				case "changed-metadata":
					path, want = "dist/metadata.json", "tag archive report changed"
				case "changed-checksum-order":
					path, want = "dist/checksums.txt", "tag archive report changed"
				case "changed-effective-config":
					path, want = "dist/config.yaml", "tag archive report changed"
				case "unindexed-output":
					path = "dist/unindexed-inert"
				}
				p := filepath.Join(root, path)
				original, e := os.ReadFile(p)
				if name == "unindexed-output" {
					if !os.IsNotExist(e) {
						t.Fatal("unexpected preexisting fixture output")
					}
					writeFixture(t, p, []byte("inert extra output"))
					defer os.Remove(p)
				} else {
					if e != nil {
						t.Fatal(e)
					}
					defer writeFixture(t, p, original)
					switch name {
					case "missing-linux-archive", "missing-darwin-archive":
						if e := os.Remove(p); e != nil {
							t.Fatal(e)
						}
					case "changed-metadata":
						var m map[string]any
						if e := json.Unmarshal(original, &m); e != nil {
							t.Fatal(e)
						}
						m["date"] = "2000-01-02T00:00:00Z"
						b, _ := json.Marshal(m)
						writeFixture(t, p, b)
					case "changed-checksum-order":
						lines := strings.Split(string(original), "\n")
						writeFixture(t, p, []byte(lines[1]+"\n"+lines[0]+"\n"))
					default:
						writeFixture(t, p, append(append([]byte(nil), original...), '\n'))
					}
				}
				cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), args...)
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off")
				var out, errout boundedOutput
				cmd.Stdout, cmd.Stderr = &out, &errout
				e = cmd.Run()
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || out.b.Len() != 0 || out.overflow || errout.overflow || !strings.Contains(errout.b.String(), want) {
					t.Fatalf("stale physical-output binder refusal %s missing: %v %q", name, e, errout.b.String())
				}
			})
		}

	})
	t.Logf("local synthetic tag=%s source=%s tree=%s; real compiler/archive bytes; no engine or plugin execution", tag, sha, before.Tree)
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
	root, _, _ := newSourceFixture(t)
	// Use the actual checkout's formatted manifest. A compact synthetic JSON
	// object hides normalization during the capture/receipt/verify crossing.
	originalManifest, e := os.ReadFile("../plugin.json")
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "plugin.json"), originalManifest)
	fixtureGit(t, root, "add", "plugin.json")
	fixtureGit(t, root, "commit", "-qm", "actual formatted manifest fixture")
	sha := fixtureGit(t, root, "rev-parse", "HEAD")
	before, e := captureSource(root, sha)
	if e != nil {
		t.Fatal(e)
	}
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
	// Official v2.20.3 artifact enum/String/JSON tags (artifact.go blob
	// 2cd550fa9ad2fcce89822b2b4ea367af617f849b): WingetLocale shifts
	// Metadata to 36. This literal also comes from the isolated exact-source
	// serializer probe; it is not evidence of GoReleaser archive execution.
	var metadataArtifact releaseArtifact
	if e = decodeExact([]byte(`{"name":"metadata.json","path":"dist/metadata.json","internal_type":36,"type":"Metadata"}`), &metadataArtifact); e != nil {
		t.Fatal(e)
	}
	artifacts = append(artifacts, releaseArtifact{Name: "checksums.txt", Path: "dist/checksums.txt", Type: "Checksum", Internal: 12}, metadataArtifact)
	index, e := json.Marshal(artifacts)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index)
	receiptBytes, e := os.ReadFile(stateFile)
	if e != nil {
		t.Fatal(e)
	}
	var capturedReceipt sourceState
	if e = decodeExact(receiptBytes, &capturedReceipt); e != nil {
		t.Fatal(e)
	}
	t.Logf("manifest original bytes=%d sha256=%s; decoded receipt bytes=%d sha256=%s; recorded sha256=%s", len(originalManifest), checksumBytes(originalManifest), len(capturedReceipt.Manifest), checksumBytes(capturedReceipt.Manifest), capturedReceipt.Files["plugin.json"].SHA256)
	output := fixtureTool(t, root, []string{"GO111MODULE=off"}, "run", script, "verify", sha, stateFile, filepath.Join(owned, "extracted"))
	var report archiveReport
	if e = decodeExact(output, &report); e != nil || len(report.Archives) != 2 || report.Commit != sha {
		t.Fatalf("actual CLI refused synthetic producer bytes: %v", e)
	}
	t.Run("legacy-snapshot-report-shape", func(t *testing.T) {
		var fields map[string]json.RawMessage
		if e := json.Unmarshal(output, &fields); e != nil {
			t.Fatal(e)
		}
		var got string
		if e := json.Unmarshal(fields["snapshot_version"], &got); e != nil || got != version {
			t.Fatal("legacy snapshot version wire field changed")
		}
		for _, key := range []string{"tag", "tag_version", "verification_mode"} {
			if _, ok := fields[key]; ok {
				t.Fatal("tag fields leaked into legacy snapshot report")
			}
		}
	})
	for _, tc := range []struct {
		name, diagnostic string
		mutate           func(map[string]any)
	}{
		{"metadata-v2.16.0-code", "artifact wire type mismatch", func(m map[string]any) { m["internal_type"] = 35 }},
		{"metadata-other-enum", "artifact wire type mismatch", func(m map[string]any) { m["internal_type"] = 37 }},
		{"metadata-missing-code", "artifact wire type mismatch", func(m map[string]any) { delete(m, "internal_type") }},
		{"metadata-zero-code", "artifact wire type mismatch", func(m map[string]any) { m["internal_type"] = 0 }},
		{"metadata-conflicting-label", "artifact wire type mismatch", func(m map[string]any) { m["type"] = "Binary" }},
		{"metadata-conflicting-code", "artifact wire type mismatch", func(m map[string]any) { m["internal_type"] = 4 }},
		{"metadata-string-code", "cannot unmarshal string", func(m map[string]any) { m["internal_type"] = "36" }},
		{"metadata-unknown-field", "unknown field", func(m map[string]any) { m["unrecognized_wire_field"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bad []map[string]any
			if e := json.Unmarshal(index, &bad); e != nil {
				t.Fatal(e)
			}
			m := bad[len(bad)-1]
			if m["name"] != "metadata.json" || m["internal_type"] != float64(36) || m["type"] != "Metadata" {
				t.Fatal("official metadata mutation input changed")
			}
			tc.mutate(m)
			b, e := json.Marshal(bad)
			if e != nil {
				t.Fatal(e)
			}
			writeFixture(t, filepath.Join(root, "dist/artifacts.json"), b)
			defer writeFixture(t, filepath.Join(root, "dist/artifacts.json"), index)
			extract := filepath.Join(owned, "refusal-"+tc.name)
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "run", script, "verify", sha, stateFile, extract)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
			var stdout, stderr boundedOutput
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || stdout.b.Len() != 0 || stdout.overflow || stderr.overflow || !strings.Contains(stderr.b.String(), tc.diagnostic) {
				t.Fatalf("actual CLI did not enforce wire refusal %s: %v", tc.name, err)
			}
			if _, e := os.Lstat(extract); !os.IsNotExist(e) {
				t.Fatal("wire refusal created extraction output")
			}
		})
	}
	t.Run("original-manifest-raw-byte-binding", func(t *testing.T) {
		if !bytes.Equal(report.Source.Manifest, originalManifest) || report.Source.Files["plugin.json"].SHA256 != checksumBytes(originalManifest) {
			t.Fatal("actual capture/verify receipt did not preserve original manifest bytes")
		}
	})
	for _, tc := range []struct{ name, diagnostic string }{
		{"receipt-bytes", "original manifest receipt mismatch"},
		{"manifest-content", "manifest changed beyond version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := stateFile
			if tc.name == "receipt-bytes" {
				b, err := os.ReadFile(stateFile)
				if err != nil {
					t.Fatal(err)
				}
				var bad sourceState
				if err = decodeExact(b, &bad); err != nil {
					t.Fatal(err)
				}
				// Valid JSON, same meaning, different original raw bytes. The
				// existing recorded hash must reject this receipt alteration.
				bad.Manifest = append([]byte(" "), bad.Manifest...)
				b, err = json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				receipt = filepath.Join(owned, "altered-receipt.json")
				writeFixture(t, receipt, b)
			} else {
				from := []byte(`"author": "GoCodeAlone"`)
				if bytes.Count(manifest, from) != 1 {
					t.Fatal("actual manifest mutation control missing")
				}
				writeFixture(t, filepath.Join(root, "plugin.json"), bytes.Replace(manifest, from, []byte(`"author": "inert changed author"`), 1))
				defer writeFixture(t, filepath.Join(root, "plugin.json"), manifest)
			}
			extract := filepath.Join(owned, "refusal-"+tc.name)
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "run", script, "verify", sha, receipt, extract)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
			var stdout, stderr boundedOutput
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || stdout.b.Len() != 0 || stdout.overflow || stderr.overflow || !strings.Contains(stderr.b.String(), "archive qualification: "+tc.diagnostic) {
				t.Fatalf("actual CLI did not enforce %s: %v", tc.name, err)
			}
			if _, err := os.Lstat(extract); !os.IsNotExist(err) {
				t.Fatal("manifest refusal created extraction output")
			}
		})
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

func TestTagRecheckTemporaryPlacement(t *testing.T) {
	for _, child := range []bool{false, true} {
		t.Run(map[bool]string{false: "source-root", true: "inside-source"}[child], func(t *testing.T) {
			root := t.TempDir()
			temp := root
			if child {
				temp = filepath.Join(root, "inside")
				if e := os.Mkdir(temp, 0700); e != nil {
					t.Fatal(e)
				}
			}
			t.Setenv("TMPDIR", temp)
			e := revalidateTagArchiveReport(root, strings.Repeat("1", 40), "inert", &archiveReport{}, nil)
			if e == nil || !strings.Contains(e.Error(), "temporary directory must be outside source") {
				t.Fatalf("source-local temporary placement accepted: %v", e)
			}
			entries, e := os.ReadDir(temp)
			if e != nil || len(entries) != 0 {
				t.Fatal("refused placement created source output")
			}
		})
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

func TestQualificationRejectsLegacyPrereleaseTag(t *testing.T) {
	root, sha, before := newSourceFixture(t)
	legacy := "v0.0.0-qualification.g" + sha
	fixtureGit(t, root, "tag", "--no-sign", legacy, sha)
	if e := qualificationTagIdentity(root, sha, before.Tree, legacy); e == nil {
		t.Fatal("legacy incompatible qualification tag accepted")
	}
}
