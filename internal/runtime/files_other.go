//go:build !windows

package runtime

import "path/filepath"

func resolveTrustedDirectory(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
