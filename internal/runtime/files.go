package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func atomicWrite(path string, b []byte, mode os.FileMode) error {

	if err := noSymlinks(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := noSymlinks(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".aswired-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

func noSymlinks(path string) error {
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		s, e := os.Lstat(p)
		if e == nil && !s.Mode().IsRegular() && !s.IsDir() {

			return errors.New("refusing symbolic link or special file in managed path")
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		up := filepath.Dir(p)
		if up == p {
			break
		}
		p = up
	}
	return nil
}

func safeName(s string) bool {
	if s == "" || len(s) > 120 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return !strings.Contains(s, "..") && s != "."
}

func canonicalManagedRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("data directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(absolute, 0700); err != nil {
		return "", err
	}
	canonical, err := resolveTrustedDirectory(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve data directory: %w", err)
	}
	return filepath.Abs(canonical)
}

func rebaseManagedPath(path, configuredRoot, canonicalRoot string) (string, error) {
	if path == "" {
		return "", nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(configuredRoot, absolute)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
		return filepath.Join(canonicalRoot, relative), nil
	}
	return absolute, nil
}
