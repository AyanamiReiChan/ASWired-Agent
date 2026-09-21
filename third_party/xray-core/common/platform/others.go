//go:build !windows
// +build !windows

package platform

import (
	"os"
	"path/filepath"
)

func LineSeparator() string {
	return "\n"
}

func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	defPath := filepath.Join(assetPath, file)
	for _, p := range []string{
		defPath,
		filepath.Join("/usr/local/share/xray/", file),
		filepath.Join("/usr/share/xray/", file),
		filepath.Join("/opt/share/xray/", file),
	} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		return p
	}

	return defPath
}

func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}
