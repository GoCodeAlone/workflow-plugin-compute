//go:build ignore

// Run with go test acquire-release-engine.go acquire-release-engine_test.go.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var inertEngine = []byte("inert fixture; never executed\n")

func fixtureSHA(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func acquireFixture(t *testing.T) (string, string) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source")
	parent := filepath.Join(root, "owned")
	if e = os.MkdirAll(filepath.Join(source, "scripts"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("install-release-engine.sh")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(source, "scripts/install-release-engine.sh"), b, 0600); e != nil {
		t.Fatal(e)
	}
	return source, parent
}
func inertResponse() *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("benign archive stand-in\n")), ContentLength: -1}
}
func writeInertInstalled(cmd *exec.Cmd) error {
	dest := cmd.Args[len(cmd.Args)-1]
	if e := os.Mkdir(dest, 0700); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dest, "goreleaser"), inertEngine, 0500)
}
func inertOptions() engineAcquireOptions {
	return engineAcquireOptions{fetch: func(*http.Request) (*http.Response, error) { return inertResponse(), nil }, extract: writeInertInstalled, binarySHA: fixtureSHA(inertEngine)}
}

func TestAcquireOrderedInertHandoff(t *testing.T) {
	source, parent := acquireFixture(t)
	var output bytes.Buffer
	var events []string
	opt := inertOptions()
	opt.fetch = func(req *http.Request) (*http.Response, error) {
		events = append(events, "download")
		if req.URL.String() != releaseEngineURL || req.Method != "GET" || req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("request policy drift")
		}
		return inertResponse(), nil
	}
	opt.extract = func(cmd *exec.Cmd) error {
		events = append(events, "extract")
		if cmd.Path != "/bin/bash" || len(cmd.Args) != 5 || cmd.Args[1] != filepath.Join(source, "scripts/install-release-engine.sh") || cmd.Args[2] != "linux-amd64" || cmd.Dir != source {
			t.Fatal("extractor invocation drift")
		}
		want := []string{"PATH=/usr/bin:/bin", "HOME=" + filepath.Join(filepath.Dir(cmd.Args[3]), "home"), "TMPDIR=" + filepath.Join(filepath.Dir(cmd.Args[3]), "tmp"), "LANG=C", "LC_ALL=C"}
		if !reflect.DeepEqual(cmd.Env, want) {
			t.Fatal("extractor inherited ambient environment")
		}
		b, e := os.ReadFile(cmd.Args[3])
		if e != nil || string(b) != "benign archive stand-in\n" {
			t.Fatal("download handoff differs")
		}
		fi, e := os.Stat(cmd.Args[3])
		if e != nil || fi.Mode().Perm() != 0600 {
			t.Fatal("archive mode differs")
		}
		return writeInertInstalled(cmd)
	}
	if e := runEngineAcquire([]string{source, parent}, &output, opt); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(events, []string{"download", "extract"}) {
		t.Fatal("order differs")
	}
	installed := strings.TrimSuffix(output.String(), "\n")
	if !strings.HasPrefix(installed, parent+string(filepath.Separator)) || filepath.Base(installed) != "goreleaser" || strings.Count(output.String(), "\n") != 1 {
		t.Fatal("success path differs")
	}
	// The injected pin binds harmless fixture bytes only, never a distribution.
	b, e := os.ReadFile(installed)
	if e != nil || !bytes.Equal(b, inertEngine) {
		t.Fatal("inert result differs")
	}
}
func TestAcquireInvalidInputs(t *testing.T) {
	for _, kind := range []string{"arity", "relative-source", "relative-parent", "newline", "missing-parent", "missing-helper", "symlink-helper"} {
		t.Run(kind, func(t *testing.T) {
			source, parent := acquireFixture(t)
			args := []string{source, parent}
			switch kind {
			case "arity":
				args = nil
			case "relative-source":
				args[0] = "."
			case "relative-parent":
				args[1] = "owned"
			case "newline":
				args[1] += "\n"
			case "missing-parent":
				args[1] = filepath.Join(parent, "missing")
			case "missing-helper":
				os.Remove(filepath.Join(source, "scripts/install-release-engine.sh"))
			case "symlink-helper":
				p := filepath.Join(source, "scripts/install-release-engine.sh")
				b, _ := os.ReadFile(p)
				os.Remove(p)
				target := filepath.Join(source, "inert-target")
				os.WriteFile(target, b, 0600)
				os.Symlink(target, p)
			}
			calls := 0
			opt := inertOptions()
			opt.fetch = func(*http.Request) (*http.Response, error) { calls++; return inertResponse(), nil }
			var out bytes.Buffer
			if e := runEngineAcquire(args, &out, opt); e == nil || calls != 0 || out.Len() != 0 {
				t.Fatal("invalid input reached acquisition")
			}
		})
	}
}
func TestAcquireHelperBinding(t *testing.T) {
	for _, when := range []string{"before-download", "after-download"} {
		t.Run(when, func(t *testing.T) {
			source, parent := acquireFixture(t)
			helper := filepath.Join(source, "scripts/install-release-engine.sh")
			b, _ := os.ReadFile(helper)
			tamper := func() {
				if e := os.WriteFile(helper, append(b, []byte("\n# inert fixture change\n")...), 0600); e != nil {
					t.Fatal(e)
				}
			}
			downloads, extracts := 0, 0
			opt := inertOptions()
			if when == "before-download" {
				tamper()
			}
			opt.fetch = func(*http.Request) (*http.Response, error) {
				downloads++
				if when == "after-download" {
					tamper()
				}
				return inertResponse(), nil
			}
			opt.extract = func(cmd *exec.Cmd) error { extracts++; return writeInertInstalled(cmd) }
			var out bytes.Buffer
			if e := runEngineAcquire([]string{source, parent}, &out, opt); e == nil || out.Len() != 0 || extracts != 0 {
				t.Fatal("helper mutation accepted")
			}
			if when == "before-download" && downloads != 0 {
				t.Fatal("unauthenticated helper reached transport")
			}
		})
	}
}

type acquireBody struct {
	io.Reader
	closed   bool
	closeErr error
}

func (b *acquireBody) Close() error { b.closed = true; return b.closeErr }

type repeatByte struct{}

func (repeatByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) {
	return 0, errors.New("inert private transport detail")
}
func TestAcquireDownloadRefusals(t *testing.T) {
	for _, kind := range []string{"transport", "nil-response", "status", "declared-size", "stream-size", "empty", "read-error", "close-error", "extract-error"} {
		t.Run(kind, func(t *testing.T) {
			source, parent := acquireFixture(t)
			body := &acquireBody{Reader: strings.NewReader("benign fixture\n")}
			response := &http.Response{StatusCode: 200, Body: body, ContentLength: -1}
			extracts := 0
			opt := inertOptions()
			switch kind {
			case "status":
				response.StatusCode = 404
			case "declared-size":
				response.ContentLength = releaseEngineMaxBytes + 1
			case "stream-size":
				body.Reader = io.LimitReader(repeatByte{}, releaseEngineMaxBytes+1)
			case "empty":
				body.Reader = strings.NewReader("")
			case "read-error":
				body.Reader = failureReader{}
			case "close-error":
				body.closeErr = errors.New("inert private close detail")
			}
			opt.fetch = func(*http.Request) (*http.Response, error) {
				if kind == "transport" {
					return nil, errors.New("inert private transport detail")
				}
				if kind == "nil-response" {
					return nil, nil
				}
				return response, nil
			}
			opt.extract = func(cmd *exec.Cmd) error {
				extracts++
				if kind == "extract-error" {
					return errors.New("inert private child detail")
				}
				return writeInertInstalled(cmd)
			}
			var out bytes.Buffer
			e := runEngineAcquire([]string{source, parent}, &out, opt)
			if e == nil || out.Len() != 0 || strings.Contains(e.Error(), "private") {
				t.Fatal("failed acquisition emitted success or raw error")
			}
			if kind == "extract-error" && !strings.Contains(e.Error(), "strict extraction failed") {
				t.Fatal("extractor failure phase was lost")
			}
			if kind != "extract-error" && extracts != 0 {
				t.Fatal("refused download reached extractor")
			}
			if kind != "transport" && kind != "nil-response" && !body.closed {
				t.Fatal("response body not closed")
			}
		})
	}
}
func TestAcquireProductionPinRefusesInertResult(t *testing.T) {
	source, parent := acquireFixture(t)
	opt := inertOptions()
	opt.binarySHA = ""
	var out bytes.Buffer
	if e := runEngineAcquire([]string{source, parent}, &out, opt); e == nil || !strings.Contains(e.Error(), "installed engine authentication") || out.Len() != 0 {
		t.Fatal("production binary pin was bypassed")
	}
}
func TestAcquireInstalledRefusals(t *testing.T) {
	for _, kind := range []string{"missing", "link", "mode"} {
		t.Run(kind, func(t *testing.T) {
			source, parent := acquireFixture(t)
			opt := inertOptions()
			opt.extract = func(cmd *exec.Cmd) error {
				dest := cmd.Args[len(cmd.Args)-1]
				if e := os.Mkdir(dest, 0700); e != nil {
					return e
				}
				switch kind {
				case "link":
					p := filepath.Join(filepath.Dir(dest), "inert-target")
					if e := os.WriteFile(p, inertEngine, 0500); e != nil {
						return e
					}
					return os.Symlink(p, filepath.Join(dest, "goreleaser"))
				case "mode":
					return os.WriteFile(filepath.Join(dest, "goreleaser"), inertEngine, 0600)
				}
				return nil
			}
			var out bytes.Buffer
			if e := runEngineAcquire([]string{source, parent}, &out, opt); e == nil || out.Len() != 0 {
				t.Fatal("invalid installed result accepted")
			}
		})
	}
}
func TestAcquireRealExtractorDigestRefusal(t *testing.T) {
	source, parent := acquireFixture(t)
	opt := inertOptions()
	opt.extract = nil
	var out bytes.Buffer
	if e := runEngineAcquire([]string{source, parent}, &out, opt); e == nil || !strings.Contains(e.Error(), "strict extraction failed") || out.Len() != 0 {
		t.Fatal("actual extractor did not refuse inert unauthenticated bytes")
	}
	roots, e := os.ReadDir(parent)
	if e != nil || len(roots) != 1 {
		t.Fatal("owned failure input not retained")
	}
	if _, e = os.Lstat(filepath.Join(parent, roots[0].Name(), "engine")); !os.IsNotExist(e) {
		t.Fatal("unauthenticated archive reached destination creation")
	}
}

type inertRoundTripper func(*http.Request) (*http.Response, error)

func (f inertRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAcquireHTTPPolicy(t *testing.T) {
	client := releaseEngineClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || client.Timeout != 60*time.Second || client.Jar != nil || transport.Proxy != nil || transport.DialContext == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || !transport.DisableCompression || !transport.DisableKeepAlives {
		t.Fatal("HTTP limits/ambient-policy drift")
	}
	for _, target := range []struct {
		name, location string
		accepted       bool
	}{
		{"official-asset", "https://release-assets.githubusercontent.com/owned/inert", true},
		{"unapproved-host", "https://example.invalid/inert", false},
		{"plaintext", "http://github.com/inert", false},
		{"userinfo", "https://inert@github.com/inert", false},
		{"port", "https://github.com:444/inert", false},
	} {
		t.Run(target.name, func(t *testing.T) {
			client := releaseEngineClient()
			calls := 0
			client.Transport = inertRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
					t.Fatal("credentials reached redirect")
				}
				if calls == 1 {
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{target.location}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("inert")), Request: req}, nil
			})
			request, _ := http.NewRequest("GET", releaseEngineURL, nil)
			response, e := client.Do(request)
			if target.accepted {
				if e != nil || calls != 2 {
					t.Fatal("official redirect refused")
				}
				response.Body.Close()
			} else if e == nil || calls != 1 {
				t.Fatal("unexpected redirect accepted")
			}
		})
	}
	req, _ := http.NewRequest("GET", releaseEngineURL, nil)
	if e := client.CheckRedirect(req, make([]*http.Request, 4)); e == nil {
		t.Fatal("redirect limit absent")
	}
	u, _ := url.Parse("https://github.com:443/inert")
	req.URL = u
	if e := client.CheckRedirect(req, nil); e == nil {
		t.Fatal("explicit redirect port accepted")
	}
	if releaseEngineURL != "https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/goreleaser_Linux_x86_64.tar.gz" || releaseEngineBinarySHA != "d124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d" || releaseEngineHelperSHA != "9c1ce84cca15098821f4597fcc7fda12a65bcaffce47e31636f43516f51af083" || releaseEngineMaxBytes != 64<<20 {
		t.Fatal("acquisition pins/bound drift")
	}
}
