//go:build ignore

// Acquire one immutable public Linux release engine. Never execute it. Both
// release and credential-free tag rehearsal call this entry point. The parent
// supplies stable owned paths; this is not an adversarial filesystem race guard.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	releaseEngineURL             = "https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/goreleaser_Linux_x86_64.tar.gz"
	releaseEngineHelperSHA       = "9c1ce84cca15098821f4597fcc7fda12a65bcaffce47e31636f43516f51af083"
	releaseEngineBinarySHA       = "d124b61b79baf6d7e2727bb018e7115c045c076df82c13795bb19f9ace4b612d"
	releaseEngineMaxBytes  int64 = 64 << 20
)

// Private seams support inert offline fixtures. main accepts no transport,
// command, URL or pin override and always uses the fixed production defaults.
type engineAcquireOptions struct {
	fetch     func(*http.Request) (*http.Response, error)
	extract   func(*exec.Cmd) error
	binarySHA string
}

func releaseEngineClient() *http.Client {
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableCompression: true, DisableKeepAlives: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			host := req.URL.Hostname()
			if len(via) > 3 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Port() != "" || (host != "github.com" && host != "release-assets.githubusercontent.com") {
				return errors.New("release engine redirect refused")
			}
			return nil
		},
	}
}
func engineFileSHA(path string, max int64) (string, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > max {
		return "", errors.New("invalid release engine input")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("release engine input unreadable")
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(f, max+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || n > max {
		return "", errors.New("release engine input read failed")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
func engineHelperAuthentic(helper string) bool {
	sum, e := engineFileSHA(helper, 1<<20)
	return e == nil && sum == releaseEngineHelperSHA
}
func runEngineAcquire(args []string, out io.Writer, opt engineAcquireOptions) error {
	if len(args) != 2 {
		return errors.New("expected absolute SOURCE OWNED_PARENT")
	}
	for _, p := range args {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return errors.New("noncanonical acquisition path")
		}
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("acquisition directory unavailable")
		}
	}
	source, parent := args[0], args[1]
	helper := filepath.Join(source, "scripts/install-release-engine.sh")
	if !engineHelperAuthentic(helper) {
		return errors.New("strict extractor authentication failed")
	}
	owned, e := os.MkdirTemp(parent, "release-engine-")
	if e != nil {
		return errors.New("owned engine directory creation failed")
	}
	// Keep this fresh owned directory on failure. No caller path is removed.
	home, tmp := filepath.Join(owned, "home"), filepath.Join(owned, "tmp")
	for _, p := range []string{home, tmp} {
		if e = os.Mkdir(p, 0700); e != nil {
			return errors.New("owned engine directory setup failed")
		}
	}
	if opt.fetch == nil {
		opt.fetch = releaseEngineClient().Do
	}
	if opt.extract == nil {
		opt.extract = func(cmd *exec.Cmd) error { return cmd.Run() }
	}
	if opt.binarySHA == "" {
		opt.binarySHA = releaseEngineBinarySHA
	}
	request, e := http.NewRequest("GET", releaseEngineURL, nil)
	if e != nil {
		return errors.New("release engine request setup failed")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, e := opt.fetch(request)
	if e != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return errors.New("release engine download failed")
	}
	if response == nil || response.Body == nil {
		return errors.New("release engine response missing")
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > releaseEngineMaxBytes {
		response.Body.Close()
		return errors.New("release engine response refused")
	}
	archive := filepath.Join(owned, "engine.tar.gz")
	f, e := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		response.Body.Close()
		return errors.New("exclusive engine archive creation failed")
	}
	n, readErr := io.Copy(f, io.LimitReader(response.Body, releaseEngineMaxBytes+1))
	fileErr := f.Close()
	bodyErr := response.Body.Close()
	if readErr != nil || fileErr != nil || bodyErr != nil || n == 0 || n > releaseEngineMaxBytes {
		return errors.New("release engine download incomplete or excessive")
	}
	if !engineHelperAuthentic(helper) {
		return errors.New("strict extractor authentication changed")
	}
	destination := filepath.Join(owned, "engine")
	cmd := exec.Command("/bin/bash", helper, "linux-amd64", archive, destination)
	cmd.Dir = source
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + tmp, "LANG=C", "LC_ALL=C"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = opt.extract(cmd); e != nil {
		return errors.New("strict extraction failed")
	}
	binary := filepath.Join(destination, "goreleaser")
	sum, e := engineFileSHA(binary, 128<<20)
	st, statErr := os.Lstat(binary)
	if e != nil || statErr != nil || st.Mode().Perm() != 0500 || sum != opt.binarySHA {
		return errors.New("installed engine authentication failed")
	}
	if _, e = fmt.Fprintln(out, binary); e != nil {
		return errors.New("installed engine path output failed")
	}
	return nil
}
func main() {
	if e := runEngineAcquire(os.Args[1:], os.Stdout, engineAcquireOptions{}); e != nil {
		fmt.Fprintln(os.Stderr, "release engine acquisition:", e)
		os.Exit(1)
	}
}
