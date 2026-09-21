//go:build windows
// +build windows

package platform

import "path/filepath"

func LineSeparator() string {
	return "\r\n"
}

func GetAssetLocation(file string) string {
	assetPath := NewEnvFlag(AssetLocation).GetValue(getExecutableDir)
	return filepath.Join(assetPath, file)
}

func GetCertLocation(file string) string {
	certPath := NewEnvFlag(CertLocation).GetValue(getExecutableDir)
	return filepath.Join(certPath, file)
}
