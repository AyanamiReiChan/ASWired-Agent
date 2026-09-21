package common

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

var ErrNoClue = errors.New("not enough information for making a decision")

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func Must2[T any](v T, err error) T {
	Must(err)
	return v
}

func Error2(v interface{}, err error) error {
	return err
}

func envFile() (string, error) {
	if file := os.Getenv("GOENV"); file != "" {
		if file == "off" {
			return "", errors.New("GOENV=off")
		}
		return file, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", errors.New("missing user-config dir")
	}
	return filepath.Join(dir, "go", "env"), nil
}

func GetRuntimeEnv(key string) (string, error) {
	file, err := envFile()
	if err != nil {
		return "", err
	}
	if file == "" {
		return "", errors.New("missing runtime env file")
	}
	var data []byte
	var runtimeEnv string
	data, readErr := os.ReadFile(file)
	if readErr != nil {
		return "", readErr
	}
	envStrings := strings.Split(string(data), "\n")
	for _, envItem := range envStrings {
		envItem = strings.TrimSuffix(envItem, "\r")
		envKeyValue := strings.Split(envItem, "=")
		if strings.EqualFold(strings.TrimSpace(envKeyValue[0]), key) {
			runtimeEnv = strings.TrimSpace(envKeyValue[1])
		}
	}
	return runtimeEnv, nil
}

func GetGOBIN() string {

	GOBIN := os.Getenv("GOBIN")
	if GOBIN == "" {
		var err error

		GOBIN, err = GetRuntimeEnv("GOBIN")
		if err != nil {

			return filepath.Join(build.Default.GOPATH, "bin")
		}
		if GOBIN == "" {
			return filepath.Join(build.Default.GOPATH, "bin")
		}
		return GOBIN
	}
	return GOBIN
}

func GetGOPATH() string {

	GOPATH := os.Getenv("GOPATH")
	if GOPATH == "" {
		var err error

		GOPATH, err = GetRuntimeEnv("GOPATH")
		if err != nil {

			return build.Default.GOPATH
		}
		if GOPATH == "" {
			return build.Default.GOPATH
		}
		return GOPATH
	}
	return GOPATH
}

func GetModuleName(pathToProjectRoot string) (string, error) {
	var moduleName string
	loopPath := pathToProjectRoot
	for {
		if idx := strings.LastIndex(loopPath, string(filepath.Separator)); idx >= 0 {
			gomodPath := filepath.Join(loopPath, "go.mod")
			gomodBytes, err := os.ReadFile(gomodPath)
			if err != nil {
				loopPath = loopPath[:idx]
				continue
			}

			gomodContent := string(gomodBytes)
			moduleIdx := strings.Index(gomodContent, "module ")
			newLineIdx := strings.Index(gomodContent, "\n")

			if moduleIdx >= 0 {
				if newLineIdx >= 0 {
					moduleName = strings.TrimSpace(gomodContent[moduleIdx+6 : newLineIdx])
					moduleName = strings.TrimSuffix(moduleName, "\r")
				} else {
					moduleName = strings.TrimSpace(gomodContent[moduleIdx+6:])
				}
				return moduleName, nil
			}
			return "", fmt.Errorf("can not get module path in `%s`", gomodPath)
		}
		break
	}
	return moduleName, fmt.Errorf("no `go.mod` file in every parent directory of `%s`", pathToProjectRoot)
}

func CloseIfExists(obj any) error {
	if obj != nil {
		v := reflect.ValueOf(obj)
		if !v.IsNil() {
			return Close(obj)
		}
	}
	return nil
}
