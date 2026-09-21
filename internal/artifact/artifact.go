package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const MaxBytes = 256 << 20

var exactVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)

func validatePin(checksum, version string) error {
	b, e := hex.DecodeString(checksum)
	if e != nil || len(b) != 32 {
		return errors.New("release SHA256 must be exactly 64 hexadecimal characters")
	}
	if !exactVersion.MatchString(version) {
		return errors.New("an exact release version is required")
	}
	return nil
}
func Verify(ctx context.Context, path, checksum, version string) error {
	if e := validatePin(checksum, version); e != nil {
		return e
	}
	stat, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxBytes {
		return errors.New("artifact must be a regular file up to 256 MiB")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	hash := sha256.New()
	_, e = io.Copy(hash, f)
	f.Close()
	if e != nil {
		return e
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), checksum) {
		return errors.New("artifact SHA256 differs from the pinned release")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, path, "-version").Output()
	if e != nil {
		return errors.New("verified artifact did not report its version")
	}
	if strings.TrimSpace(string(out)) != version {
		return errors.New("artifact version differs from the selected release")
	}
	return nil
}
func artifactURL(value string) bool {
	u, e := url.Parse(value)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback())
}
func Fetch(ctx context.Context, value, destination, checksum, version string) error {
	if e := validatePin(checksum, version); e != nil {
		return e
	}
	if !artifactURL(value) {
		return errors.New("artifact URL must use HTTPS (HTTP is only permitted for local tests)")
	}
	if !filepath.IsAbs(destination) {
		return errors.New("artifact staging output must be an absolute path")
	}
	if _, e := os.Lstat(destination); e == nil {
		return errors.New("staging destination already exists")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(destination), 0700); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "GET", value, nil)
	if e != nil {
		return e
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || !artifactURL(req.URL.String()) {
			return errors.New("invalid artifact redirect")
		}
		return nil
	}}
	res, e := client.Do(request)
	if e != nil {
		return errors.New("artifact download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("artifact download returned a non-success status")
	}
	f, e := os.CreateTemp(filepath.Dir(destination), ".aswired-artifact-*.exe")
	if e != nil {
		return e
	}
	path := f.Name()
	defer os.Remove(path)
	n, e := io.Copy(f, io.LimitReader(res.Body, MaxBytes+1))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if n > MaxBytes {
		return errors.New("artifact exceeds 256 MiB")
	}
	if e = os.Chmod(path, 0755); e != nil {
		return e
	}
	if e = Verify(ctx, path, checksum, version); e != nil {
		return e
	}
	return os.Rename(path, destination)
}
